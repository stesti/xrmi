/*
 * SR2QueryResponder.{cc,hh} -- DSR implementation
 * John Bicket
 *
 * Copyright (c) 1999-2001 Massachussr2queryresponders Institute of Technology
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
#include "sr2queryrespondermulti.hh"
#include <click/ipaddress.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <clicknet/ether.h>
#include "availableinterfaces.hh"
#include "arptablemulti.hh"
#include "sr2packetmulti.hh"
#include "sr2linktablemulti.hh"
#include "sr2pathmulti.hh"
CLICK_DECLS

SR2QueryResponderMulti::SR2QueryResponderMulti()
  :  _ip(),
     _et(0),
     _link_table(0),
     _arp_table(0)
{
}

SR2QueryResponderMulti::~SR2QueryResponderMulti()
{
}

int
SR2QueryResponderMulti::configure (Vector<String> &conf, ErrorHandler *errh)
{
  int ret;
  _debug = false;
  ret = cp_va_kparse(conf, this, errh,
		     "ETHTYPE", 0, cpUnsignedShort, &_et,
		     "IP", 0, cpIPAddress, &_ip,
		     "LT", 0, cpElement, &_link_table,
		     "IT", 0, cpElement, &_if_table,
		     "ARP", 0, cpElement, &_arp_table,
		     "DEBUG", 0, cpBool, &_debug,
		     cpEnd);

  if (!_et) 
    return errh->error("ETHTYPE not specified");
  if (!_ip) 
    return errh->error("IP not specified");
  if (!_link_table) 
    return errh->error("LT not specified");
  if (!_arp_table) 
    return errh->error("ARPTable not specified");
  if (_link_table->cast("SR2LinkTableMulti") == 0) 
    return errh->error("SR2LinkTableMulti element is not a SR2LinkTableMulti");
  if (_if_table && _if_table->cast("AvailableInterfaces") == 0) 
    return errh->error("AvailableInterfaces element is not an AvailableInterfaces");
  if (_arp_table->cast("ARPTableMulti") == 0) 
    return errh->error("ARPTableMulti element is not a ARPTableMulti");

  return ret;
}

int
SR2QueryResponderMulti::initialize (ErrorHandler *)
{
  return 0;
}

void
SR2QueryResponderMulti::send(WritablePacket *p)
{
  click_ether *eh = (click_ether *) p->data();
  struct sr2packetmulti *pk = (struct sr2packetmulti *) (eh+1);
  int next = pk->next();
  IPAddress next_ip = pk->get_link_node(next);
  uint16_t next_if = pk->get_link_if(next);
  //EtherAddress eth_dest = _arp_table->lookup(NodeAddress(next_ip,next_if));
	EtherAddress eth_dest = _arp_table->lookup_def(NodeAddress(next_ip,next_if));

  assert(next_ip != _ip);
  eh->ether_type = htons(_et);
  //EtherAddress my_eth = _if_table->lookup_if(pk->get_link_if_b(next));
	EtherAddress my_eth = _if_table->lookup_def();
  memcpy(eh->ether_shost, my_eth.data(), 6);
  memcpy(eh->ether_dhost, eth_dest.data(), 6);

  output(0).push(p);
}

bool
SR2QueryResponderMulti::update_link(NodeAddress from, NodeAddress to, 
			      uint32_t seq, uint32_t metric) {
  if (!from || !to || !metric) {
    return false;
  }
  if (!_link_table->update_link(from, to, seq, 0, metric)) {
    click_chatter("%{element} :: %s :: couldn't update link %s-%d > %d > %s-%d",
		  this,
		  __func__,
		  from._ipaddr.unparse().c_str(),
		  from._iface,
		  metric,
		  to._ipaddr.unparse().c_str(),
		  to._iface);
    return false;
  }
  return true;
}

void
SR2QueryResponderMulti::forward_reply(struct sr2packetmulti *pk)
{

  _link_table->dijkstra(true);
  if (_debug) {
    click_chatter("%{element} :: %s :: forward_reply %s <- %s", 
		  this,
		  __func__,
		  pk->get_link_node(0).unparse().c_str(),
		  pk->qdst().unparse().c_str());
  }
  if(pk->next() >= pk->num_links()) {
    click_chatter("%{element} :: %s :: forward_reply strange next=%d, nhops=%d", 
		  this,
		  __func__,
		  pk->next(), 
		  pk->num_links());
    return;
  }

  SR2PathMulti fwd;
  SR2PathMulti rev;
  //for (int i = 0; i < pk->num_links(); i++) {
  //  fwd.push_back(NodeAirport(pk->get_link_node(i),pk->get_link_if(i)));
  //}
  fwd = pk->get_path();
  rev = reverse_path(fwd);

  int len = pk->hlen_wo_data();
  WritablePacket *p = Packet::make(len + sizeof(click_ether));
  if(p == 0)
    return;
  click_ether *eh = (click_ether *) p->data();
  struct sr2packetmulti *pk_send = (struct sr2packetmulti *) (eh+1);
  memcpy(pk_send, pk, len);

  pk_send->set_next(pk->next() - 1);

  send(p);

}

void 
SR2QueryResponderMulti::start_reply(IPAddress src, IPAddress qdst, uint32_t seq)
{
  _link_table->dijkstra(false);
  SR2PathMulti best = _link_table->best_route(src, false);
  bool best_valid = _link_table->valid_route(best);
  int si = 0;
  
  for(si = 0; si < _seen.size(); si++){
    if(src == _seen[si]._src && seq == _seen[si]._seq) {
      break;
    }
  }

  if (si == _seen.size()) {
    if (_seen.size() >= 100) {
      _seen.pop_front();
    }
    _seen.push_back(Seen(src, qdst, seq));
    si = _seen.size() - 1;
  }

  if (best == _seen[si].last_path_response) {
    /*
     * only send replies if the "best" path is different
     * from the last reply
     */
    return;
  }

  _seen[si]._src = src;
  _seen[si]._dst = qdst;
  _seen[si]._seq = seq;
  _seen[si].last_path_response = best;
  
  if (!best_valid) {
    click_chatter("%{element} :: %s :: invalid route for src %s: %s",
		  this,
		  __func__,
		  src.unparse().c_str(),
		  path_to_string(best).c_str());
    return;
  }
  int links = best.size() - 1;
  int len = sr2packetmulti::len_wo_data(links);
  if (_debug) {
    click_chatter("%{element} :: %s :: start reply %s <- %s",
		  this,
		  __func__,
		  src.unparse().c_str(),
		  qdst.unparse().c_str());
  }
  WritablePacket *p = Packet::make(len + sizeof(click_ether));
  if(p == 0)
    return;
  click_ether *eh = (click_ether *) p->data();
  struct sr2packetmulti *pk_out = (struct sr2packetmulti *) (eh+1);
  memset(pk_out, '\0', len);

  pk_out->_version = _sr2_version;
  pk_out->_type = SR2_PT_REPLY;
  pk_out->unset_flag(~0);
  pk_out->set_seq(seq);
  pk_out->set_num_links(links);
  pk_out->set_next(links-1);
  pk_out->set_qdst(qdst);
  
  for (int i = 0; i < links; i++) {
    pk_out->set_link(i,
		     best[i].get_dep(), best[i+1].get_arr(),
		     _link_table->get_link_metric(best[i].get_dep(), best[i+1].get_arr()),
		     _link_table->get_link_metric(best[i+1].get_dep(), best[i].get_arr()),
		     _link_table->get_link_seq(best[i].get_dep(), best[i+1].get_arr()),
		     _link_table->get_link_age(best[i].get_dep(), best[i+1].get_arr()));
  }
  
  send(p);
}

void
SR2QueryResponderMulti::push(int, Packet *p_in)
{

  click_ether *eh = (click_ether *) p_in->data();
  struct sr2packetmulti *pk = (struct sr2packetmulti *) (eh+1);
 
  // I'm the ultimate consumer of this query. Going to answer it.
  if (pk->_type == SR2_PT_QUERY) {
    IPAddress dst = pk->qdst();
    if (dst == _ip) {
      click_chatter("%{element} :: %s :: query for me %s",
  		    this,
		    __func__,
		    dst.unparse().c_str());
      start_reply(pk->get_link_node(0), pk->qdst(), pk->seq());
    }
    p_in->kill();
    return;
  }

  if (eh->ether_type != htons(_et)) {
    click_chatter("%{element} :: %s :: bad ether_type %04x",
					this,
					__func__,
					ntohs(eh->ether_type));
    p_in->kill();
    return;
  }

  if (pk->_type != SR2_PT_REPLY) {
    click_chatter("%{element} :: %s :: bad packet_type %04x",
					this,
					__func__,
					_ip.unparse().c_str(),
					pk->_type);
    p_in->kill();
    return;
  }

  if(pk->get_link_node(pk->next()) != _ip){
    // It's not for me. these are supposed to be unicast,
    // so how did this get to me?
    click_chatter("%{element} :: %s :: reply not for me %d/%d %s",
		  this,
		  __func__,
		  pk->next(),
		  pk->num_links(),
		  pk->get_link_node(pk->next()).unparse().c_str());
    p_in->kill();
    return;
  }
  /* update the metrics from the packet */
  for(int i = 0; i < pk->num_links(); i++) {
    NodeAddress a = NodeAddress(pk->get_link_node(i),pk->get_link_if(i));
    NodeAddress b = NodeAddress(pk->get_link_node_b(i),pk->get_link_if_b(i));
    int fwd_m = pk->get_link_fwd(i);
    int rev_m = pk->get_link_fwd(i);
    uint32_t seq = pk->get_link_seq(i);
    if (fwd_m && !update_link(a,b,seq,fwd_m)) {
      click_chatter("%{element} :: %s :: couldn't update fwd_m %s > %d > %s",
		    this,
  		    __func__,
		    a._ipaddr.unparse().c_str(),
		    fwd_m,
		    b._ipaddr.unparse().c_str());
    }
    if (rev_m && !update_link(b,a,seq,rev_m)) {
      click_chatter("%{element} :: %s :: couldn't update rev_m %s > %d > %s",
		    this,
  		    __func__,
		    b._ipaddr.unparse().c_str(),
		    rev_m,
		    a._ipaddr.unparse().c_str());
    }
  }
  
  	/*
  IPAddress neighbor = pk->get_link_node_b(pk->next());
  int neighborif = pk->get_link_if_b(pk->next());

  if (_arp_table) {
		click_chatter("%{element} :: %s :: QUERYDEBUG recvd reply ARP %s %s-%d\n", 
		  this,
			__func__,
			EtherAddress(eh->ether_shost).unparse().c_str(),
			neighbor.unparse().c_str(),
			neighborif);
		_arp_table->insert(NodeAddress(neighbor,neighborif), EtherAddress(eh->ether_shost));
  }
	*/
  
  if(pk->next() == 0){
    // I'm the ultimate consumer of this reply. Add to routing tbl.
	IPAddress dst = pk->qdst();
		if (_debug) {
			click_chatter("%{element} :: %s :: got reply %s <- %s", 
			      this,
			      __func__,
			      _ip.unparse().c_str(),
			      dst.unparse().c_str());
		}
		
   		_link_table->dijkstra(true);

  } else {
    // Forward the reply.
    forward_reply(pk);
  }
  p_in->kill();
  return;
    
}

enum {H_DEBUG, H_IP};

String
SR2QueryResponderMulti::read_handler(Element *e, void *thunk)
{
  SR2QueryResponderMulti *td = (SR2QueryResponderMulti *)e;
  switch ((uintptr_t) thunk) {
  case H_DEBUG:
    return String(td->_debug) + "\n";
  case H_IP:
    return td->_ip.unparse() + "\n";
  default:
    return String();
  }
}

int 
SR2QueryResponderMulti::write_handler(const String &in_s, Element *e, void *vparam,
		     ErrorHandler *errh)
{
  SR2QueryResponderMulti *f = (SR2QueryResponderMulti *)e;
  String s = cp_uncomment(in_s);
  switch((intptr_t)vparam) {
  case H_DEBUG: {  
    bool debug;
    if (!cp_bool(s, &debug)) 
      return errh->error("debug parameter must be boolean");
    f->_debug = debug;
    break;
  }
  }
  return 0;
}

void
SR2QueryResponderMulti::add_handlers()
{
  add_read_handler("debug", read_handler, H_DEBUG);
  add_read_handler("ip", read_handler, H_IP);

  add_write_handler("debug", write_handler, H_DEBUG);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(SR2LinkMetricMulti)
EXPORT_ELEMENT(SR2QueryResponderMulti)

