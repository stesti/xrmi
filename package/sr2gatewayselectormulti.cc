/*
 * SR2GatewaySelector.{cc,hh} -- DSR implementation
 * John Bicket
 *
 * Copyright (c) 1999-2001 Massachusetts Institute of Technology
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
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/ipaddress.hh>
#include <clicknet/ether.h>
#include "arptablemulti.hh"
#include "availableinterfaces.hh"
#include "sr2packetmulti.hh"
#include "sr2linktablemulti.hh"
#include "sr2nodemulti.hh"
#include "sr2gatewayselectormulti.hh"
CLICK_DECLS

SR2GatewaySelectorMulti::SR2GatewaySelectorMulti()
  :  _ip(),
     _et(0),
     _link_table(0),
     _if_table(0),
     _arp_table(0),
     _timer(this)
{
  // Pick a starting sequence number that we have not used before.
  _seq = Timestamp::now().usec();
}

SR2GatewaySelectorMulti::~SR2GatewaySelectorMulti()
{
}

int
SR2GatewaySelectorMulti::configure (Vector<String> &conf, ErrorHandler *errh)
{
  int ret;
  _is_gw = false;
  ret = cp_va_kparse(conf, this, errh,
		     "ETHTYPE", 0, cpUnsignedShort, &_et,
		     "IP", 0, cpIPAddress, &_ip,
		     "LT", 0, cpElement, &_link_table,
		     "IT", 0, cpElement, &_if_table,
		     "ARP", 0, cpElement, &_arp_table,
		     "PERIOD", 0, cpUnsigned, &_period,
		     "JITTER", 0, cpUnsigned, &_jitter,
		     "EXPIRE", 0, cpUnsigned, &_expire,
		     "GW", 0, cpBool, &_is_gw,
		     cpEnd);

  if (!_et) 
    return errh->error("ETHTYPE not specified");
  if (!_ip) 
    return errh->error("IP not specified");
  if (!_link_table) 
    return errh->error("LT not specified");
  if (_link_table->cast("SR2LinkTableMulti") == 0) 
    return errh->error("LinkTable element is not a SR2LinkTableMulti");
  if (_if_table && _if_table->cast("AvailableInterfaces") == 0) 
    return errh->error("AvailableInterfaces element is not an AvailableInterfaces");
  if (_arp_table && _arp_table->cast("ARPTableMulti") == 0) 
    return errh->error("ARPTable element is not an ARPtableMulti");

  return ret;
}

int
SR2GatewaySelectorMulti::initialize (ErrorHandler *)
{
  _timer.initialize (this);
  _timer.schedule_now ();

  return 0;
}

void
SR2GatewaySelectorMulti::run_timer (Timer *)
{
  cleanup();
  if (_is_gw) {
    start_ad();
  }
  unsigned max_jitter = _period / 10;
  unsigned j = click_random(0, 2 * max_jitter);
  Timestamp delay = Timestamp::make_msec(_period + j - max_jitter);
  _timer.schedule_at(Timestamp::now() + delay);
}

void
SR2GatewaySelectorMulti::start_ad()
{

  HashMap<EtherAddress,AvailableInterfaces::LocalIfInfo> my_iftable = _if_table->get_if_list();

	int len = sr2packetmulti::len_wo_data(1);
	WritablePacket *p = Packet::make(len + sizeof(click_ether));
	if(p == 0)
	  return;
	click_ether *eh = (click_ether *) p->data();
	struct sr2packetmulti *pk = (struct sr2packetmulti *) (eh+1);
	memset(pk, '\0', len);
	pk->_version = _sr2_version;
	pk->_type = SR2_PT_GATEWAY;
	pk->unset_flag(~0);
	pk->set_qdst(_ip);
	pk->set_seq(++_seq);
	pk->set_num_links(0);
	pk->set_link_node(0,_ip);

	EtherAddress my_eth = _if_table->lookup_def();
	int my_iface = _if_table->lookup_def_id();
	
	pk->set_link_if(0,my_iface);

	send(p,my_eth);
  
}

void
SR2GatewaySelectorMulti::send(WritablePacket *p, EtherAddress my_eth)
{
  click_ether *eh = (click_ether *) p->data();
  eh->ether_type = htons(_et);
  memcpy(eh->ether_shost, my_eth.data(), 6);
  memset(eh->ether_dhost, 0xff, 6);
  output(0).push(p);
}

bool
SR2GatewaySelectorMulti::update_link(NodeAddress from, NodeAddress to, uint32_t seq, 
			     uint32_t metric) {
  if (_link_table && !_link_table->update_link(from, to, seq, 0, metric)) {
    click_chatter("%{element} :: %s :: couldn't update link %s > %d > %s\n",
		  this,
		  __func__,
		  from._ipaddr.unparse().c_str(),
		  metric,
		  to._ipaddr.unparse().c_str());
    return false;
  }
  return true;
}

void
SR2GatewaySelectorMulti::forward_ad_hook() 
{
    Timestamp now = Timestamp::now();
    for (int x = 0; x < _seen.size(); x++) {
	if (_seen[x]._to_send < now && !_seen[x]._forwarded) {
	    forward_ad(&_seen[x]);
	}
    }
}

void
SR2GatewaySelectorMulti::forward_ad(Seen *s)
{

  s->_forwarded = true;
  _link_table->dijkstra(false);
  IPAddress src = s->_gw;
  SR2PathMulti best = _link_table->best_route(src, false);
  
  if (!_link_table->valid_route(best)) {
    click_chatter("%{element} :: %s :: invalid route from src %s\n",
		  this,
		  __func__,
		  src.unparse().c_str());
    return;
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
  pk->_type = SR2_PT_GATEWAY;
  pk->unset_flag(~0);
  pk->set_qdst(s->_gw);
  pk->set_seq(s->_seq);
  pk->set_num_links(links);

  for(int i=0; i < links; i++) {
    pk->set_link(i, best[i].get_dep(), best[i+1].get_arr(),
		  _link_table->get_link_metric(best[i].get_dep(), best[i+1].get_arr()),
		  _link_table->get_link_metric(best[i+1].get_dep(), best[i].get_arr()),
		  _link_table->get_link_seq(best[i].get_dep(), best[i+1].get_arr()),
		  _link_table->get_link_age(best[i].get_dep(), best[i+1].get_arr()));
  }

  //EtherAddress my_eth = _if_table->lookup_if(best[links].get_arr()._iface);
	EtherAddress my_eth = _if_table->lookup_def();
	
  send(p,my_eth);
}

IPAddress
SR2GatewaySelectorMulti::best_gateway() 
{
  IPAddress best_gw = IPAddress();
  int best_metric = 0;
  Timestamp now = Timestamp::now();
  
  for(GWIter iter = _gateways.begin(); iter.live(); iter++) {
    GWInfo nfo = iter.value();
    Timestamp expire = nfo._last_update + Timestamp::make_msec(_expire);
    SR2PathMulti p = _link_table->best_route(nfo._ip, false);
    int metric = _link_table->get_route_metric(p);
    if (now < expire &&
				metric && 
				((!best_metric) || best_metric > metric) &&
				!_ignore.findp(nfo._ip) &&
				(!_allow.size() || _allow.findp(nfo._ip))) {
					best_gw = nfo._ip;
      		best_metric = metric;
    }
  }
  
  return best_gw;
}

void 
SR2GatewaySelectorMulti::cleanup() {

  GWTable new_table;
  Timestamp now = Timestamp::now();
  for(GWIter iter = _gateways.begin(); iter.live(); iter++) {
    GWInfo nfo = iter.value();
    Timestamp expire = nfo._last_update + Timestamp::make_msec(_expire);  
    if (now < expire) {
      new_table.insert(nfo._ip, nfo);
    }
  }
  _gateways.clear();
  for(GWIter iter = new_table.begin(); iter.live(); iter++) {
    GWInfo nfo = iter.value();
    _gateways.insert(nfo._ip, nfo);
  }
}

void
SR2GatewaySelectorMulti::push(int, Packet *p_in)
{
  click_ether *eh = (click_ether *) p_in->data();
  struct sr2packetmulti *pk = (struct sr2packetmulti *) (eh+1);
  if(eh->ether_type != htons(_et)) {
    click_chatter("%{element} :: %s :: %s bad ether_type %04x",
		  this,
		  __func__,
		  _ip.unparse().c_str(),
		  ntohs(eh->ether_type));
    p_in->kill();
    return;
  }
  if (pk->_type != SR2_PT_GATEWAY) {
    click_chatter("%{element} :: %s :: back packet type %d",
		  this,
		  __func__,
		  pk->_type);
    p_in->kill();
    return;
  }
  for(int i = 0; i < pk->num_links(); i++) {
    IPAddress a = pk->get_link_node(i);
    uint16_t aif = pk->get_link_if(i);
    IPAddress b = pk->get_link_node_b(i);
    uint16_t bif = pk->get_link_if_b(i);
    uint32_t fwd_m = pk->get_link_fwd(i);
    uint32_t rev_m = pk->get_link_rev(i);
    uint32_t seq = pk->get_link_seq(i);
    if (a == _ip || b == _ip || !fwd_m || !rev_m || !seq) {
      p_in->kill();
      return;
    }
    if (fwd_m && !update_link(NodeAddress(a,aif),NodeAddress(b,bif),seq,fwd_m)) {
      click_chatter("%{element} :: %s :: couldn't update fwd_m %s > %d > %s\n",
		    this,
		    __func__,
		    a.unparse().c_str(),
		    fwd_m,
		    b.unparse().c_str());
    }
    if (rev_m && !update_link(NodeAddress(b,bif),NodeAddress(a,aif),seq,rev_m)) {
      click_chatter("%{element} :: %s :: couldn't update rev_m %s > %d > %s\n",
		    this,
		    __func__,
		    b.unparse().c_str(),
		    rev_m,
		    a.unparse().c_str());
    }
  }

	if (pk->num_links() == 0) {
		IPAddress neighbor = pk->get_link_node(0);
	  uint16_t neighborif = pk->get_link_if(0);
	  if (_arp_table) {
			_arp_table->insert(NodeAddress(neighbor,neighborif), EtherAddress(eh->ether_shost));
	  }
	}

  
  IPAddress gw = pk->qdst();
  if (!gw) {
	  p_in->kill();
	  return;
  }

  int si = 0;
  uint32_t seq = pk->seq();
  for(si = 0; si < _seen.size(); si++){
    if(gw == _seen[si]._gw && seq == _seen[si]._seq){
      _seen[si]._count++;
      p_in->kill();
      return;
    }
  }

  if (si == _seen.size()) {
    if (_seen.size() == 100) {
      _seen.pop_front();
      si--;
    }
    _seen.push_back(Seen(gw, seq, 0, 0));
  }
  _seen[si]._count++;

  GWInfo *nfo = _gateways.findp(gw);
  if (!nfo) {
	  _gateways.insert(gw, GWInfo());
	  nfo = _gateways.findp(gw);
	  nfo->_first_update = Timestamp::now();
      nfo->_seen = 0;
  }
  
  nfo->_ip = gw;
  nfo->_last_update = Timestamp::now();
  nfo->_seen++;

  if (_is_gw) {
    p_in->kill();
    return;
  }

  /* schedule timer */
  int delay = click_random(1, _jitter);
  
  _seen[si]._to_send = _seen[si]._when + Timestamp::make_msec(delay);
  _seen[si]._forwarded = false;
  Timer *t = new Timer(static_forward_ad_hook, (void *) this);
  t->initialize(this);
  t->schedule_after_msec(delay);

  p_in->kill();
  return;
}

String
SR2GatewaySelectorMulti::print_gateway_stats()
{
    StringAccum sa;
    Timestamp now = Timestamp::now();
    for(GWIter iter = _gateways.begin(); iter.live(); iter++) {
      GWInfo nfo = iter.value();
      sa << nfo._ip.unparse().c_str() << " ";
      sa << "seen " << nfo._seen << " ";
      sa << "first_update " << now - nfo._first_update << " ";
      sa << "last_update " << now - nfo._last_update << " ";
      
      SR2PathMulti p = _link_table->best_route(nfo._ip, false);
      int metric = _link_table->get_route_metric(p);
      sa << "current_metric " << metric << "\n";
    }
    
  return sa.take_string();
}

enum { H_IS_GATEWAY, H_GATEWAY_STATS, H_ALLOW, H_ALLOW_ADD, H_ALLOW_DEL, H_ALLOW_CLEAR, H_IGNORE, H_IGNORE_ADD, H_IGNORE_DEL, H_IGNORE_CLEAR};

String
SR2GatewaySelectorMulti::read_handler(Element *e, void *thunk)
{
  SR2GatewaySelectorMulti *f = (SR2GatewaySelectorMulti *)e;
  switch ((uintptr_t) thunk) {
  case H_IS_GATEWAY:
    return String(f->_is_gw) + "\n";
  case H_GATEWAY_STATS:
    return f->print_gateway_stats();
  case H_IGNORE: {
    StringAccum sa;
    for (IPIter iter = f->_ignore.begin(); iter.live(); iter++) {
      IPAddress ip = iter.key();
      sa << ip << "\n";
    }
    return sa.take_string();    
  }
  case H_ALLOW: {
    StringAccum sa;
    for (IPIter iter = f->_allow.begin(); iter.live(); iter++) {
      IPAddress ip = iter.key();
      sa << ip << "\n";
    }
    return sa.take_string();    
  }
  default:
    return String();
  }
}

int 
SR2GatewaySelectorMulti::write_handler(const String &in_s, Element *e, void *vparam,
		     ErrorHandler *errh)
{
  SR2GatewaySelectorMulti *f = (SR2GatewaySelectorMulti *)e;
  String s = cp_uncomment(in_s);
  switch((intptr_t)vparam) {
    case H_IS_GATEWAY: {  
      bool b;
      if (!cp_bool(s, &b)) 
        return errh->error("is_gateway parameter must be boolean");
      f->_is_gw = b;
      break;
    }
    case H_IGNORE_ADD: {  
      IPAddress ip;
      if (!cp_ip_address(s, &ip)) {
        return errh->error("ignore_add parameter must be IPAddress");
      }
      f->_ignore.insert(ip, ip);
      break;
    }
    case H_IGNORE_DEL: {  
      IPAddress ip;
      if (!cp_ip_address(s, &ip)) {
        return errh->error("ignore_add parameter must be IPAddress");
      }
      f->_ignore.remove(ip);
      break;
    }
    case H_IGNORE_CLEAR: {  
      f->_ignore.clear();
      break;
    }
    case H_ALLOW_ADD: {  
      IPAddress ip;
      if (!cp_ip_address(s, &ip)) {
        return errh->error("ignore_add parameter must be IPAddress");
      }
      f->_allow.insert(ip, ip);
      break;
    }
    case H_ALLOW_DEL: {  
      IPAddress ip;
      if (!cp_ip_address(s, &ip)) {
        return errh->error("ignore_add parameter must be IPAddress");
      }
      f->_allow.remove(ip);
      break;
    }
    case H_ALLOW_CLEAR: {  
      f->_allow.clear();
      break;
    }
  }
  return 0;
}

void
SR2GatewaySelectorMulti::add_handlers()
{
  add_read_handler("is_gateway", read_handler, (void *) H_IS_GATEWAY);
  add_read_handler("gateway_stats", read_handler, (void *) H_GATEWAY_STATS);
  add_read_handler("ignore", read_handler, (void *) H_IGNORE);
  add_read_handler("allow", read_handler, (void *) H_ALLOW);

  add_write_handler("is_gateway", write_handler, (void *) H_IS_GATEWAY);
  add_write_handler("ignore_add", write_handler, (void *) H_IGNORE_ADD);
  add_write_handler("ignore_del", write_handler, (void *) H_IGNORE_DEL);
  add_write_handler("ignore_clear", write_handler, (void *) H_IGNORE_CLEAR);
  add_write_handler("allow_add", write_handler, (void *) H_ALLOW_ADD);
  add_write_handler("allow_del", write_handler, (void *) H_ALLOW_DEL);
  add_write_handler("allow_clear", write_handler, (void *) H_ALLOW_CLEAR);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(SR2LinkTableMulti)
EXPORT_ELEMENT(SR2GatewaySelectorMulti)
