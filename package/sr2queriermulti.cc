/*
 * SR2QuerierMulti.{cc,hh} -- DSR implementation
 * with multiradio nodes
 * Stefano.Testi@studenti.unitn.it
 *
 * Copyright (c) 1999-2001 Massachussrcrs Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "sr2queriermulti.hh"
#include <click/ipaddress.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <clicknet/ether.h>
#include "availableinterfaces.hh"
#include "sr2forwardermulti.hh"
#include "sr2linktablemulti.hh"
#include "sr2pathmulti.hh"
CLICK_DECLS

SR2QuerierMulti::SR2QuerierMulti()
  :  _ip(),
     _et(0),
     _forwarder(0),
     _link_table(0)
{
}

SR2QuerierMulti::~SR2QuerierMulti()
{
}

int
SR2QuerierMulti::configure (Vector<String> &conf, ErrorHandler *errh)
{

  _query_wait = Timestamp(5);
  _time_before_switch_sec = Timestamp(10);
  _debug = false;

  int res;
  res = cp_va_kparse(conf, this, errh,
		     "ETHTYPE", 0, cpUnsignedShort, &_et,
		     "IP", 0, cpIPAddress, &_ip,
		     "FWD", 0, cpElement, &_forwarder,
		     "LT", 0, cpElement, &_link_table,
		     "IT", 0, cpElement, &_if_table,
		     "DEBUG", 0, cpBool, &_debug,
		     "TIME_BEFORE_SWITCH", 0, cpTimestamp, &_time_before_switch_sec,
		     "QUERY_WAIT", 0, cpTimestamp, &_query_wait,
		     cpEnd);

  if (!_et) 
    return errh->error("ETHTYPE not specified");
  if (!_ip) 
    return errh->error("IP not specified");
  if (!_forwarder) 
    return errh->error("FWD not specified");
  if (_forwarder->cast("SR2ForwarderMulti") == 0) 
    return errh->error("FWD element is not a SR2Forwarder");
  if (!_link_table) 
    return errh->error("LT not specified");
  if (_if_table && _if_table->cast("AvailableInterfaces") == 0) 
    return errh->error("AvailableInterfaces element is not an AvailableInterfaces");
  if (_link_table->cast("SR2LinkTableMulti") == 0) 
    return errh->error("LT element is not a SR2LinkTableMulti");

  return res;
}

void
SR2QuerierMulti::send_query(IPAddress dst)
{
  DstInfoMulti *nfo = _queries.findp(dst);
  if (!nfo) {
    _queries.insert(dst, DstInfoMulti(dst));
    nfo = _queries.findp(dst);
  }
  nfo->_last_query.set_now();
  nfo->_count++;

  unsigned extra = sr2packetmulti::len_wo_data(0) + sizeof(click_ether);
  WritablePacket *p = Packet::make(extra);
  if (!p) {
    return;
  }

	EtherAddress my_eth = _if_table->lookup_def();
	int my_iface = _if_table->lookup_def_id();

  click_ether *eh = (click_ether *) p->data();
  eh->ether_type = htons(_et);
  memcpy(eh->ether_shost, my_eth.data(), 6);
  memset(eh->ether_dhost, 0xff, 6);
  struct sr2packetmulti *pk = (struct sr2packetmulti *) (eh+1);
  memset(pk, '\0', sr2packetmulti::len_wo_data(0));
  pk->_version = _sr2_version;
  pk->_type = SR2_PT_QUERY;
  pk->unset_flag(~0);
  pk->set_qdst(dst);
  pk->set_seq(++_seq);
  pk->set_num_links(0);
  pk->set_link_node(0,_ip);
  pk->set_data_len(0);
	pk->set_link_if(0,my_iface);
  //if (_debug) {
    click_chatter("%{element} :: %s :: start query %s %d\n",
		  this, 
		  __func__,
		  dst.unparse().c_str(), 
		  _seq);
  //}

  output(1).push(p);
}

void
SR2QuerierMulti::push(int, Packet *p_in)
{
	IPAddress dst = p_in->dst_ip_anno();
	if (!dst) {
		click_chatter("%{element} :: %s :: got invalid dst %s\n",
			      this,
			      __func__,
			      dst.unparse().c_str());
		p_in->kill();
		return;
	}
	
	DstInfoMulti *q = _queries.findp(dst);
	if (!q) {
		_queries.insert(dst, DstInfoMulti(dst));
		q = _queries.findp(dst);
		q->_best_metric = 0;
	}
	
	Timestamp now = Timestamp::now();
	Timestamp expire = q->_last_switch + _time_before_switch_sec;
	
	if (!q->_best_metric || !q->_p.size() || expire < now) {
		SR2PathMulti best = _link_table->best_route(dst, true);
		bool valid = _link_table->valid_route(best);
		q->_last_switch.set_now();
		if (valid) {
			if (q->_p != best) {
				q->_first_selected.set_now();
			}
			q->_p = best;
			q->_best_metric = _link_table->get_route_metric(best);
		} else {
			q->_p = SR2PathMulti();
			q->_best_metric = 0;
		}
	}
	
	if (q->_best_metric) {
		p_in = _forwarder->encap(p_in, q->_p, 0);
		if (p_in) {
			output(0).push(p_in);
		}
		return;
	} 

	if (_debug) {
		click_chatter("%{element} :: %s :: no valid route to %s\n",
			      this, 
			      __func__, 
			      dst.unparse().c_str());
	}

	p_in->kill();

	if ((q->_last_query + _query_wait) < Timestamp::now()) {

	 	send_query(dst);

	}

	return;

}

String
SR2QuerierMulti::print_queries()
{
  StringAccum sa;
  Timestamp now = Timestamp::now();
  for (DstTableMulti::const_iterator iter = _queries.begin(); iter.live(); iter++) {
    DstInfoMulti dst = iter.value();
    SR2PathMulti best = _link_table->best_route(dst._ip, true);
    int current_path_metric = _link_table->get_route_metric(dst._p);
    int best_metric = _link_table->get_route_metric(best);
    sa << dst._ip << "-";
    sa << " query_count " << dst._count;
    sa << " best_metric " << dst._best_metric;
    sa << " last_query_ago " << now - dst._last_query;
    sa << " first_selected_ago " << now - dst._first_selected;
    sa << " last_switch_ago " << now - dst._last_switch;
    sa << " current_path_metric " << current_path_metric;
    sa << " [ " << path_to_string(dst._p) << " ]";
    sa << " best_metric " << best_metric;
    sa << " best_route [ " << path_to_string(best) << " ]";
    sa << "\n";
  }
  return sa.take_string();
}

enum {H_DEBUG, H_RESET, H_QUERIES, H_QUERY};

String
SR2QuerierMulti::read_handler(Element *e, void *thunk)
{
  SR2QuerierMulti *c = (SR2QuerierMulti *)e;
  switch ((intptr_t)(thunk)) {
  case H_DEBUG:
    return String(c->_debug) + "\n";
  case H_QUERIES:
    return c->print_queries();
  default:
    return "<error>\n";
  }
}

int 
SR2QuerierMulti::write_handler(const String &in_s, Element *e, void *vparam,
		     ErrorHandler *errh)
{
  SR2QuerierMulti *td = (SR2QuerierMulti *)e;
  String s = cp_uncomment(in_s);
  switch ((intptr_t)vparam) {
    case H_DEBUG: {
      bool debug;
      if (!cp_bool(s, &debug)) 
        return errh->error("debug parameter must be boolean");
      td->_debug = debug;
      break;
    }
    case H_QUERY: {
      IPAddress dst;
      if (!cp_ip_address(s, &dst)) 
        return errh->error("query parameter must be IPAddress");	
  
      td->send_query(dst);

      break;
    }
    case H_RESET: {
      td->_queries.clear();
      break;
    }
  }
  return 0;
}

void
SR2QuerierMulti::add_handlers()
{
  add_read_handler("queries", read_handler, H_QUERIES);
  add_read_handler("debug", read_handler, H_DEBUG);

  add_write_handler("debug", write_handler, H_DEBUG);
  add_write_handler("reset", write_handler, H_RESET);
  add_write_handler("query", write_handler, H_QUERY);
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(SR2LinkMetricMulti)
EXPORT_ELEMENT(SR2QuerierMulti)

