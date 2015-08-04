/*
 * SR2SetGateway.{cc,hh} -- element tracks tcp flows sent to gateways
 * John Bicket
 * A lot of code ripped from lookupiprouteron.cc by Alexander Yip
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
#include "sr2setgatewaymulti.hh"
#include <click/ipaddress.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <clicknet/ether.h>
#include <click/packet_anno.hh>
CLICK_DECLS

SR2SetGatewayMulti::SR2SetGatewayMulti()
  :  _gw_sel(0),
     _timer(this)
{

}

SR2SetGatewayMulti::~SR2SetGatewayMulti()
{
}

int
SR2SetGatewayMulti::configure (Vector<String> &conf, ErrorHandler *errh)
{
  _gw = IPAddress();
  _period = 60000;
  int ret;
  ret = cp_va_kparse(conf, this, errh,
		     "GW", 0, cpIPAddress, &_gw,
		     "SEL", 0, cpElement, &_gw_sel,
		     "PERIOD", 0, cpUnsigned, &_period,
		     cpEnd);

  if (_gw_sel && _gw_sel->cast("SR2GatewaySelectorMulti") == 0) 
    return errh->error("SR2GatewaySelectorMulti element is not a SR2GatewaySelectorMulti");
  if (!_gw_sel && !_gw) {
    return errh->error("Either GW or SEL must be specified!\n");
  }

  return ret;
}

int
SR2SetGatewayMulti::initialize (ErrorHandler *)
{
  _timer.initialize (this);
  _timer.schedule_now ();

  return 0;
}

void
SR2SetGatewayMulti::run_timer (Timer *)
{
  cleanup();
  _timer.schedule_after_msec(_period);
}

void 
SR2SetGatewayMulti::push_fwd(Packet *p_in, IPAddress best_gw) 
{
	const click_tcp *tcph = p_in->tcp_header();
	IPFlowID flowid = IPFlowID(p_in);
	FlowTableEntry *match = _flow_table.findp(flowid);
	
	if ((tcph->th_flags & TH_SYN) && match && match->is_pending()) {
		match->_outstanding_syns++;
		p_in->set_dst_ip_anno(match->_gw);
		output(0).push(p_in);
		return;
	}  else if (!(tcph->th_flags & TH_SYN)) {
		if (match) {
			match->saw_forward_packet();
			if (tcph->th_flags & (TH_RST | TH_FIN)) {
				match->_fwd_alive = false; // forward flow is over
			}
			if (tcph->th_flags & TH_RST) {
				match->_rev_alive = false; // rev flow is over
			}
			p_in->set_dst_ip_anno(match->_gw);
			output(0).push(p_in);
			return;
		}
		
		click_chatter("%{element} :: %s :: no match guessing for %s\n",
			      this, 
			      __func__, 
			      flowid.unparse().c_str());
	}
	
	if (!best_gw) {
		p_in->kill();
		return;
	}

	/* no match */
	_flow_table.insert(flowid, FlowTableEntry());
	match = _flow_table.findp(flowid);
	match->_id = flowid;
	match->_gw = best_gw;
	match->saw_forward_packet();
	match->_outstanding_syns++;
	p_in->set_dst_ip_anno(best_gw);
	output(0).push(p_in);
}


void 
SR2SetGatewayMulti::push_rev(Packet *p_in) 
{
	const click_tcp *tcph = p_in->tcp_header();
	IPFlowID flowid = IPFlowID(p_in).reverse();
	FlowTableEntry *match = _flow_table.findp(flowid);
	
	if ((tcph->th_flags & TH_SYN) && (tcph->th_flags & TH_ACK)) {
		if (match) {
			if (match->_gw != MISC_IP_ANNO(p_in)) {
				click_chatter("%{element} :: %s :: flow %s got packet from weird gw %s, expected %s\n",
					      this, 
						  __func__,
					      flowid.unparse().c_str(),
					      p_in->dst_ip_anno().unparse().c_str(),
					      match->_gw.unparse().c_str());
				p_in->kill();
				return;
			}
			match->saw_reply_packet();
			match->_outstanding_syns = 0;
			output(1).push(p_in);
			return;
		}
		
		click_chatter("%{element} :: %s :: no match  killing SYN_ACK\n", this, __func__);
		p_in->kill();
		return;
	}
	
	/* not a syn-ack packet */
	if (match) {
		match->saw_reply_packet();
		if (tcph->th_flags & (TH_FIN | TH_RST)) {
			match->_rev_alive = false;
		}
		if (tcph->th_flags & TH_RST) {
			match->_fwd_alive = false;
		}
		output(1).push(p_in);
		return;
	}
	
	click_chatter("%{element} :: %s :: couldn't find non-pending match, creating %s\n",
		      this, 
		      __func__, 
		      flowid.unparse().c_str());
	
	_flow_table.insert(flowid, FlowTableEntry());
	match = _flow_table.findp(flowid);
	match->_id = flowid;
	match->_gw = MISC_IP_ANNO(p_in);
	match->saw_reply_packet();
	
	output(1).push(p_in);
	return;
}

void
SR2SetGatewayMulti::push(int port, Packet *p_in)
{
  if (_gw) {
    if (port == 0) {
      p_in->set_dst_ip_anno(_gw);
    } else {
      p_in->set_dst_ip_anno(IPAddress());
    }
    output(port).push(p_in);
    return;
  } else if (!_gw_sel) {
    /* this should never happen */
    click_chatter("%{element} :: %s :: _gw and _gw_sel not specified! killing packet\n", this, __func__);
    p_in->kill();
    return;
  }

  if (p_in->ip_header()->ip_p != IP_PROTO_TCP) {
    if (port == 0 && _gw_sel) {
      /* non tcp packets go to best gw */
      IPAddress gateway = _gw_sel->best_gateway();
      p_in->set_dst_ip_anno(gateway);
    } else {
      p_in->set_dst_ip_anno(IPAddress());
    }
    output(port).push(p_in);
    return;
  }

  if (port == 0) {
    IPAddress gateway = _gw_sel->best_gateway();
    push_fwd(p_in, gateway);
  } else {
    /* incoming packet */
    push_rev(p_in);
  }
}

void 
SR2SetGatewayMulti::cleanup() {
	FlowTable new_table;
	Timestamp timeout = Timestamp::make_msec(_period);
	for(FTIter i = _flow_table.begin(); i.live(); i++) {
		FlowTableEntry f = i.value();
		if ((f.age() < timeout && f._fwd_alive) || f._rev_alive) {
			new_table.insert(f._id, f);
		}
	}
	_flow_table.clear();
	for(FTIter i = new_table.begin(); i.live(); i++) {
		FlowTableEntry f = i.value();
		_flow_table.insert(f._id, f);
	}
}

String
SR2SetGatewayMulti::print_flows()
{
  StringAccum sa;
  for(FTIter iter = _flow_table.begin(); iter.live(); iter++) {
    FlowTableEntry f = iter.value();
    sa << f._id << " gw " << f._gw << " age " << f.age() << "\n";
  }

  return sa.take_string();
}

enum { H_FLOWS, H_GATEWAY };

String
SR2SetGatewayMulti::read_handler(Element *e, void *thunk)
{
  SR2SetGatewayMulti *c = (SR2SetGatewayMulti *)e;
  switch ((intptr_t)(thunk)) {
  case H_FLOWS:
    return c->print_flows();
  case H_GATEWAY:
    return (c->_gw) ? c->_gw.unparse() + "\n" : c->_gw_sel->best_gateway().unparse() + "\n";
  default:
    return "<error>\n";
  }
}

int 
SR2SetGatewayMulti::write_handler(const String &in_s, Element *e, void *vparam,
		     ErrorHandler *errh)
{
  SR2SetGatewayMulti *d = (SR2SetGatewayMulti *)e;
  String s = cp_uncomment(in_s);
  switch ((intptr_t)vparam) {
    case H_GATEWAY: {
      IPAddress ip;
      if (!cp_ip_address(s, &ip)) {
	return errh->error("gateway parameter must be IPAddress");
      }
      if (!ip && !d->_gw_sel) {
	return errh->error("gateway cannot be %s if _gw_sel is unspecified");
      }
      d->_gw = ip;
      break;
    }
  }
  return 0;
}

void
SR2SetGatewayMulti::add_handlers()
{
  add_read_handler("flows", read_handler, H_FLOWS);
  add_read_handler("gateway", read_handler, H_GATEWAY);

  add_write_handler("gateway", write_handler, H_GATEWAY);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(SR2SetGatewayMulti)
