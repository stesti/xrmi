/*
 * SR2GatewayResponder.{cc,hh} -- DSR implementation
 * John Bicket
 *
 * Copyright (c) 1999-2001 Massachussrqueryresponders Institute of Technology
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
#include "sr2gatewayselectormulti.hh"
#include "sr2gatewayrespondermulti.hh"
CLICK_DECLS

SR2GatewayResponderMulti::SR2GatewayResponderMulti()
  :  _ip(),
     _et(0),
     _arp_table(0),
     _link_table(0),
     _if_table(0),
     _timer(this)
{
}

SR2GatewayResponderMulti::~SR2GatewayResponderMulti()
{
}

int
SR2GatewayResponderMulti::configure (Vector<String> &conf, ErrorHandler *errh)
{
  int ret;
  _debug = false;
  ret = cp_va_kparse(conf, this, errh,
		     "ETHTYPE", 0, cpUnsigned, &_et,
		     "IP", 0, cpIPAddress, &_ip,
		     "LT", 0, cpElement, &_link_table,
		     "IT", 0, cpElement, &_if_table,
		     "ARP", 0, cpElement, &_arp_table,
		     "PERIOD", 0, cpUnsigned, &_period,
		     "SEL", 0, cpElement, &_gw_sel,
		     "DEBUG", 0, cpBool, &_debug,
		     cpEnd);

  if (!_et) 
    return errh->error("ETHTYPE not specified");
  if (!_period) 
    return errh->error("PERIOD not specified");
  if (!_ip) 
    return errh->error("IP not specified");
  if (!_link_table) 
    return errh->error("LT not specified");
  if (!_arp_table) 
    return errh->error("ARPTable not specified");
  if (!_link_table) 
    return errh->error("ARPTable not specified");
  if (!_gw_sel) 
    return errh->error("ARPTableMulti not specified");
  if (_arp_table->cast("ARPTableMulti") == 0) 
    return errh->error("ARPTableMulti element is not a ARPTableMulti");
  if (_gw_sel->cast("SR2GatewaySelectorMulti") == 0) 
    return errh->error("SR2GatewaySelectorMulti element is not a SR2GatewaySelectorMulti");
  if (_link_table->cast("SR2LinkTableMulti") == 0) 
    return errh->error("SR2LinkTableMulti element is not a SR2LinkTableMulti");
  if (_if_table && _if_table->cast("AvailableInterfaces") == 0) 
    return errh->error("AvailableInterfaces element is not an AvailableInterfaces");

  return ret;
}

int
SR2GatewayResponderMulti::initialize (ErrorHandler *)
{
	_timer.initialize(this);
	_timer.schedule_now();
	return 0;
}

void
SR2GatewayResponderMulti::run_timer(Timer *)
{
	if (!_gw_sel->is_gateway()) {
		IPAddress gateway = _gw_sel->best_gateway();
		_link_table->dijkstra(false);
		SR2PathMulti best = _link_table->best_route(gateway, false);
		
		if (_link_table->valid_route(best)) {
			int links = best.size() - 1;
			int len = sr2packetmulti::len_wo_data(links);
			if (_debug) {
				click_chatter("%{element} :: %s :: start_reply %s <- %s\n",
					      this,
						  __func__,
					      gateway.unparse().c_str(),
					      _ip.unparse().c_str());
			}
			WritablePacket *p = Packet::make(len + sizeof(click_ether));
			if(p == 0)
				return;
			click_ether *eh = (click_ether *) p->data();
			struct sr2packetmulti *pk = (struct sr2packetmulti *) (eh+1);
			memset(pk, '\0', len);
			
			pk->_version = _sr2_version;
			pk->_type = SR2_PT_REPLY;
			pk->unset_flag(~0);
			pk->set_seq(0);
			pk->set_num_links(links);
			pk->set_next(links-1);
			pk->set_qdst(_ip);
			
			for (int i = 0; i < links; i++) {
				pk->set_link(i,
					     best[i].get_dep(), best[i+1].get_arr(),
					     _link_table->get_link_metric(best[i].get_dep(), best[i+1].get_arr()),
					     _link_table->get_link_metric(best[i+1].get_dep(), best[i].get_arr()),
					     _link_table->get_link_seq(best[i].get_dep(), best[i+1].get_arr()),
					     _link_table->get_link_age(best[i].get_dep(), best[i+1].get_arr()));
			}
			
			IPAddress next_ip = pk->get_link_node(pk->next());
			uint16_t next_if = pk->get_link_if(pk->next());
			EtherAddress eth_dest = _arp_table->lookup(NodeAddress(next_ip,next_if));
			EtherAddress my_eth = _if_table->lookup_if(pk->get_link_if_b(pk->next()));

			
			eh->ether_type = htons(_et);
			memcpy(eh->ether_shost, my_eth.data(), 6);
			memcpy(eh->ether_dhost, eth_dest.data(), 6);
			
			output(0).push(p);
		}	
	}

	unsigned max_jitter = _period / 10;
	unsigned j = click_random(0, 2 * max_jitter);
	Timestamp delay = Timestamp::make_msec(_period + j - max_jitter);
	_timer.schedule_at(Timestamp::now() + delay);
}

enum {H_DEBUG, H_IP};

String
SR2GatewayResponderMulti::read_handler(Element *e, void *thunk)
{
  SR2GatewayResponderMulti *c = (SR2GatewayResponderMulti *)e;
  switch ((intptr_t)(thunk)) {
  case H_IP:
    return c->_ip.unparse() + "\n";
  default:
    return "<error>\n";
  }
}

int 
SR2GatewayResponderMulti::write_handler(const String &in_s, Element *e, void *vparam,
		     ErrorHandler *errh)
{
  SR2GatewayResponderMulti *d = (SR2GatewayResponderMulti *)e;
  String s = cp_uncomment(in_s);
  switch ((intptr_t)vparam) {
    case H_DEBUG: {
      bool debug;
      if (!cp_bool(s, &debug)) 
        return errh->error("debug parameter must be boolean");
      d->_debug = debug;
      break;
    }
  }
  return 0;
}

void
SR2GatewayResponderMulti::add_handlers()
{
  add_read_handler("ip", read_handler, H_IP);
  add_write_handler("debug", write_handler, H_DEBUG);
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(SR2LinkTableMulti)
EXPORT_ELEMENT(SR2GatewayResponderMulti)
