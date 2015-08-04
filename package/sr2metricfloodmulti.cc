/*
 * SR2MetricFloodMulti.{cc,hh} -- DSR implementation
 * with multiradio nodes
 * Stefano.Testi@studenti.unitn.it
 *
 * Copyright (c) 1999-2001 Massachussr2metricfloods Institute of Technology
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
#include "sr2metricfloodmulti.hh"
#include <click/ipaddress.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <clicknet/ether.h>
#include "arptablemulti.hh"
#include "availableinterfaces.hh"
#include "sr2packetmulti.hh"
#include "sr2linktablemulti.hh"
CLICK_DECLS

SR2MetricFloodMulti::SR2MetricFloodMulti()
  :  _ip(),
     _et(0),
     _link_table(0),
     _arp_table(0),
	 _if_table(0)
{
}

SR2MetricFloodMulti::~SR2MetricFloodMulti()
{
}

int
SR2MetricFloodMulti::configure (Vector<String> &conf, ErrorHandler *errh)
{
  int ret;
  _debug = false;
  ret = cp_va_kparse(conf, this, errh,
		     "ETHTYPE", 0, cpUnsignedShort, &_et,
		     "IP", 0, cpIPAddress, &_ip,
		     "IT", 0, cpElement, &_if_table,
		     "LT", 0, cpElement, &_link_table,
		     "ARP", 0, cpElement, &_arp_table,
		     "JITTER", 0, cpUnsigned, &_jitter,
		     "DEBUG", 0, cpBool, &_debug,
		     cpEnd);

  if (!_et) 
    return errh->error("ETHTYPE not specified");
  if (!_ip) 
    return errh->error("IP not specified");
  if (!_link_table) 
    return errh->error("LT not specified");
  if (_link_table->cast("SR2LinkTableMulti") == 0) 
    return errh->error("SR2LinkTableMulti element is not a SR2LinkTableMulti");
  if (_arp_table && _arp_table->cast("ARPTableMulti") == 0) 
    return errh->error("ARPTableMulti element is not a ARPTableMulti");
  if (_if_table && _if_table->cast("AvailableInterfaces") == 0) 
    return errh->error("AvailableInterfaces element is not an AvailableInterfaces");

  return ret;
}

int
SR2MetricFloodMulti::initialize (ErrorHandler *)
{
  return 0;
}

bool
SR2MetricFloodMulti::update_link(NodeAddress from, NodeAddress to, 
			      uint32_t seq, uint32_t age,
			      uint32_t metric) {
  if (!from || !to || !metric) {
    return false;
  }
  if (_link_table && !_link_table->update_link(from, to, seq, age, metric)) {
    click_chatter("%{element} couldn't update link %s > %d > %s\n",
		  this,
		  from._ipaddr.unparse().c_str(),
		  metric,
		  to._ipaddr.unparse().c_str());
    return false;
  }
  return true;
}

void
SR2MetricFloodMulti::forward_query_hook() 
{
  Timestamp now = Timestamp::now();
  for (int x = 0; x < _seen.size(); x++) {
    if (_seen[x]._to_send < now && !_seen[x]._forwarded) {
		  EtherAddress eth = _if_table->lookup_def();
	    forward_query(&_seen[x],eth);
    }
  }
}

void
SR2MetricFloodMulti::forward_query(Seen *s, EtherAddress eth)
{

  s->_forwarded = true;
  _link_table->dijkstra(false);

  if (_debug) {
    StringAccum sa;
    sa << Timestamp::now() - s->_when;
    click_chatter("%{element} :: %s :: waited %s\n",
		  this,
		  __func__,
		  sa.take_string().c_str());
  }

  IPAddress src = s->_src;
  SR2PathMulti best = _link_table->best_route(src, false);
  bool best_valid = _link_table->valid_route(best);

  if (!best_valid) {
    if (_debug) {
      click_chatter("%{element} :: %s :: invalid route from src %s\n",
                    this,
                    __func__,
                    src.unparse().c_str());
    }
    return;
  }

  if (_debug) {
     click_chatter("%{element} :: %s ::  %s -> %s %d\n", 
		  this,
  		  __func__,
		  s->_src.unparse().c_str(),
		  s->_dst.unparse().c_str(),
		  s->_seq);
  }

  int links = best.size() - 1;

  int len = sr2packetmulti::len_wo_data(links);
  WritablePacket *p = Packet::make(len + sizeof(click_ether));
  if(p == 0)
    return;
  click_ether *eh = (click_ether *) p->data();
  struct sr2packetmulti *pk = (struct sr2packetmulti *) (eh+1);
  memset(pk, '\0', len);
  pk->_version = _sr2_version;
  pk->_type = SR2_PT_QUERY;
  pk->unset_flag(~0);
  pk->set_qdst(s->_dst);
  pk->set_seq(s->_seq);
  pk->set_num_links(links);

  for (int i = 0; i < links; i++) {
    pk->set_link(i,
		 best[i].get_dep(), best[i+1].get_arr(),
		 _link_table->get_link_metric(best[i].get_dep(), best[i+1].get_arr()),
		 _link_table->get_link_metric(best[i+1].get_dep(), best[i].get_arr()),
		 _link_table->get_link_seq(best[i].get_dep(), best[i+1].get_arr()),
		 _link_table->get_link_age(best[i].get_dep(), best[i+1].get_arr()));
  }
	       
  eh->ether_type = htons(_et);
  memcpy(eh->ether_shost, eth.data(), 6);
  memset(eh->ether_dhost, 0xff, 6);
  output(0).push(p);
}

void 
SR2MetricFloodMulti::push(int, Packet *p_in)
{
  click_ether *eh = (click_ether *) p_in->data();
  struct sr2packetmulti *pk = (struct sr2packetmulti *) (eh+1);
  if(eh->ether_type != htons(_et)) {
    click_chatter("%{element} :: %s :: bad ether_type %04x",
		  this, 
		  __func__,
		  ntohs(eh->ether_type));
    p_in->kill();
    return;
  }
  if (pk->_type != SR2_PT_QUERY) {
	click_chatter("%{element} :: %s :: bad packet_type %04x",
		this,
		__func__,
		_ip.unparse().c_str(),
		pk->_type);
    p_in->kill();
    return;
  }

  /* update the metrics from the packet */
  for(int i = 0; i < pk->num_links(); i++) {
    NodeAddress a = NodeAddress(pk->get_link_node(i),pk->get_link_if(i));
    NodeAddress b = NodeAddress(pk->get_link_node_b(i),pk->get_link_if_b(i));
    uint32_t fwd_m = pk->get_link_fwd(i);
    uint32_t rev_m = pk->get_link_fwd(i);
    uint32_t seq = pk->get_link_seq(i);
    uint32_t age = pk->get_link_age(i);

    if (fwd_m && !update_link(a, b, seq, age, fwd_m)) {
      click_chatter("%{element} :: %s :: couldn't update fwd_m %s > %d > %s\n",
		    this,
		    __func__,
		    a._ipaddr.unparse().c_str(),
		    fwd_m,
		    b._ipaddr.unparse().c_str());
    }
    if (rev_m && !update_link(b, a, seq, age, rev_m)) {
      click_chatter("%{element} :: %s :: couldn't update rev_m %s > %d > %s\n",
		    this,
		    __func__,
		    b._ipaddr.unparse().c_str(),
		    rev_m,
		    a._ipaddr.unparse().c_str());
    }
  }

  /* update the arp table from the packet */
	
	if(pk->num_links() == 0) {
		IPAddress neighbor = pk->get_link_node(0);
	  int neighborif = pk->get_link_if(0);
	  if (!neighbor) {
		  p_in->kill();
		  return;
	  }
	  if (_arp_table) {
			_arp_table->insert(NodeAddress(neighbor,neighborif), EtherAddress(eh->ether_shost));
	  }
	} else {
		IPAddress neighbor = pk->get_link_node_b(pk->num_links()-1);
	  int neighborif = pk->get_link_if_b(pk->num_links()-1);
	  if (!neighbor) {
		  p_in->kill();
		  return;
	  }
	  if (_arp_table) {
			_arp_table->insert(NodeAddress(neighbor,neighborif), EtherAddress(eh->ether_shost));
	  }
	}
  
  IPAddress src = pk->get_link_node(0);
  IPAddress dst = pk->qdst();
  uint32_t seq = pk->seq();

  int si = 0;
  
  for(si = 0; si < _seen.size(); si++){
    if(src == _seen[si]._src && seq == _seen[si]._seq) {
      _seen[si]._count++;
      p_in->kill();
      return;
    }
  }
  
  if (_seen.size() >= 100) {
    _seen.pop_front();
  }
  _seen.push_back(Seen(src, dst, seq, 0, 0));
  si = _seen.size() - 1;

  _seen[si]._count++;
  _seen[si]._when = Timestamp::now();

  if (dst == _ip) {
    /* don't forward queries for me */
    /* just spit them out the output */
    output(1).push(p_in);
    return;
  }
  /* schedule timer */
  int delay = click_random(1, _jitter);
  
  _seen[si]._to_send = _seen[si]._when + Timestamp::make_msec(delay);
  _seen[si]._forwarded = false;
  Timer *t = new Timer(static_forward_query_hook, (void *) this);
  t->initialize(this);
  t->schedule_after_msec(delay);

  p_in->kill();
  return;
}

enum {H_DEBUG, H_CLEAR, H_FLOODS};

String
SR2MetricFloodMulti::read_handler(Element *e, void *thunk)
{
  SR2MetricFloodMulti *td = (SR2MetricFloodMulti *)e;
  switch ((uintptr_t) thunk) {
  case H_DEBUG:
    return String(td->_debug) + "\n";
  case H_FLOODS: {
	  StringAccum sa;
	  int x;
	  for (x = 0; x < td->_seen.size(); x++) {
		  sa << "src " << td->_seen[x]._src;
		  sa << " dst " << td->_seen[x]._dst;
		  sa << " seq " << td->_seen[x]._seq;
		  sa << " count " << td->_seen[x]._count;
		  sa << " forwarded " << td->_seen[x]._forwarded;
		  sa << "\n";
	  }
	  return sa.take_string();
  }
  default:
    return String();
  }
}

int 
SR2MetricFloodMulti::write_handler(const String &in_s, Element *e, void *vparam,
		     ErrorHandler *errh)
{
  SR2MetricFloodMulti *f = (SR2MetricFloodMulti *)e;
  String s = cp_uncomment(in_s);
  switch((intptr_t)vparam) {
  case H_DEBUG: {  
    bool debug;
    if (!cp_bool(s, &debug)) 
      return errh->error("debug parameter must be boolean");
    f->_debug = debug;
    break;
  }
  case H_CLEAR:
    f->_seen.clear();
    break;
  }
  return 0;
}

void
SR2MetricFloodMulti::add_handlers()
{
  add_read_handler("debug", read_handler, (void *) H_DEBUG);
  add_read_handler("floods", read_handler, (void *) H_FLOODS);

  add_write_handler("debug", write_handler, (void *) H_DEBUG);
  add_write_handler("clear", write_handler, (void *) H_CLEAR);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(SR2LinkMetricMulti)
EXPORT_ELEMENT(SR2MetricFloodMulti)

