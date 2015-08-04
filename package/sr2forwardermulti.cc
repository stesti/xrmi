/*
 * SR2ForwarderMulti.{cc,hh} -- Source Route data path implementation
 * with multiradio nodes
 * Stefano.Testi@studenti.unitn.it
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
#include <click/ipaddress.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <clicknet/ether.h>
#include "arptablemulti.hh"
#include "availableinterfaces.hh"
#include "sr2forwardermulti.hh"
#include "sr2packetmulti.hh"
#include "sr2linktablemulti.hh"
CLICK_DECLS

SR2ForwarderMulti::SR2ForwarderMulti()
  :  _ip(),
  //   _eth(),
     _et(0),
     _datas(0), 
     _databytes(0),
	 _if_table(0),
     _link_table(0),
     _arp_table(0)
{
}

SR2ForwarderMulti::~SR2ForwarderMulti()
{
}

int
SR2ForwarderMulti::configure (Vector<String> &conf, ErrorHandler *errh)
{
	int res;
	res = cp_va_kparse(conf, this, errh,
			   "ETHTYPE", 0, cpUnsignedShort, &_et,
			   "IP", 0, cpIPAddress, &_ip,
			   "IT", 0, cpElement, &_if_table,
			   "ARP", 0, cpElement, &_arp_table,
			   "LT", 0, cpElement, &_link_table,
			   cpEnd);
	
	if (!_et) 
		return errh->error("ETHTYPE not specified");
	if (!_ip) 
		return errh->error("IP not specified");
	if (!_link_table) 
		return errh->error("LT not specified");
	if (!_arp_table) 
		return errh->error("ARPTable not specified");
	if (_arp_table->cast("ARPTableMulti") == 0) 
		return errh->error("ARPTable element is not a ARPTable");
	if (_link_table->cast("SR2LinkTableMulti") == 0) 
		return errh->error("LT element is not a SR2LinkTableMulti");
	if (_if_table && _if_table->cast("AvailableInterfaces") == 0) 
        	return errh->error("AvailableInterfaces element is not an AvailableInterfaces");
	if (res < 0) {
		return res;
	}
	return res;
}

int
SR2ForwarderMulti::initialize (ErrorHandler *)
{
	return 0;
}

Packet *
SR2ForwarderMulti::encap(Packet *p_in, SR2PathMulti best, int flags)
{

	assert(best.size() > 1);
	int hops = best.size() - 1;
	unsigned extra = sr2packetmulti::len_wo_data(hops) + sizeof(click_ether);
	unsigned payload_len = p_in->length();
	uint16_t ether_type = htons(_et);

	WritablePacket *p = p_in->push(extra);
	
	assert(extra + payload_len == p_in->length());

	int next = index_of(best, _ip);
	if (next < 0 || next >= hops) {
		click_chatter("%{element} :: %s :: encap couldn't find %s (%d) in path %s",
			      this,
			      __func__,
                              _ip.unparse().c_str(),
			      next, 
                              path_to_string(best).c_str());
		p_in->kill();
		return (0);
	}

	EtherAddress eth_dest = _arp_table->lookup(best[next+1].get_arr());

	if (eth_dest.is_group()) {
		click_chatter("%{element} :: %s :: arp lookup failed for %s",
			      this,
			      __func__,
			      best[next]._ipaddr.unparse().c_str());
	}

	EtherAddress eth = _if_table->lookup_if(best[next].get_dep()._iface);

	memcpy(p->data(), eth_dest.data(), 6);
	memcpy(p->data() + 6, eth.data(), 6);
	memcpy(p->data() + 12, &ether_type, 2);	
	
	struct sr2packetmulti *pk = (struct sr2packetmulti *) (p->data() + sizeof(click_ether));
	memset(pk, '\0', sr2packetmulti::len_wo_data(hops));
	
	pk->_version = _sr2_version;
	pk->_type = SR2_PT_DATA;
	pk->set_data_len(payload_len);
	pk->set_num_links(hops);
	pk->set_next(next);
	pk->set_flag(flags);
	int i;
	for (i = 0; i < hops; i++) {
		pk->set_link(i, best[i].get_dep(), best[i+1].get_arr(),
		     _link_table->get_link_metric(best[i].get_dep(), best[i+1].get_arr()),
		     _link_table->get_link_metric(best[i+1].get_dep(), best[i].get_arr()),
		     _link_table->get_link_seq(best[i].get_dep(), best[i+1].get_arr()),
		     _link_table->get_link_age(best[i].get_dep(), best[i+1].get_arr()));
	}
	
	//pk->set_link_node(hops, best[hops]._ipaddr);

	return p;
}

void
SR2ForwarderMulti::push(int, Packet *p_in)
{
	WritablePacket *p = p_in->uniqueify();
	if (!p) {
		return;
	}
	click_ether *eh = (click_ether *) p->data();
	struct sr2packetmulti *pk = (struct sr2packetmulti *) (eh+1);
	if(eh->ether_type != htons(_et)) {
		click_chatter("%{element} :: %s :: bad ether_type %04x",
			      this, 
			      __func__,
			      ntohs(eh->ether_type));
		p_in->kill();
		return;
	}
	if (pk->_type != SR2_PT_DATA) {
		click_chatter("%{element} :: %s :: bad packet_type %04x",
			      this, 
			      __func__,
			      _ip.unparse().c_str(), 
			      pk->_type);
		p->kill();
		return;
	}
	
	if (pk->get_link_node_b(pk->next()) != _ip) {
		if (!EtherAddress(eh->ether_dhost).is_group()) {
			/* 
			 * If the arp doesn't have a ethernet address, it
			 * will broadcast the packet. In this case,
			 * don't complain. But otherwise, something's up.
			 */
			click_chatter("%{element} :: %s :: data not for me %d/%d node %s-%d eth %s",
				      this, 
				      __func__,
				      pk->next(), 
				      pk->num_links(),
				      pk->get_link_node_b(pk->next()).unparse().c_str(),
							pk->get_link_if_b(pk->next()),
				      EtherAddress(eh->ether_dhost).unparse().c_str());
		}
		p->kill();
		return;
	}
	if (pk->next() == (pk->num_links()-1)){
		/* I am the ultimate consumer of this packet */
		SET_MISC_IP_ANNO(p, pk->get_link_node(0));
		output(1).push(p);
		return;
	} 
	pk->set_next(pk->next() + 1);
	EtherAddress eth_dest = _arp_table->lookup(NodeAddress(pk->get_link_node_b(pk->next()),pk->get_link_if_b(pk->next())));
	if (eth_dest.is_group()) {
		click_chatter("%{element} :: %s :: arp lookup failed for %s-%d",
			      this, 
			      __func__,
			      pk->get_link_node_b(pk->next()).unparse().c_str(),
						pk->get_link_if_b(pk->next()));
	}

	EtherAddress eth = _if_table->lookup_if(pk->get_link_if(pk->next()));

	memcpy(eh->ether_dhost, eth_dest.data(), 6);
	memcpy(eh->ether_shost, eth.data(), 6);
	output(0).push(p);
	return;
}

String
SR2ForwarderMulti::print_stats()
{
	return String(_datas) + " datas sent\n" + String(_databytes) + " bytes of data sent\n";
}

enum { H_STATS };

String
SR2ForwarderMulti::read_handler(Element *e, void *user_data)
{
    SR2ForwarderMulti *sr2f = static_cast<SR2ForwarderMulti *>(e);
    switch (reinterpret_cast<uintptr_t>(user_data)) {
    case H_STATS:
	return sr2f->print_stats();
    }
    return String();
}

void
SR2ForwarderMulti::add_handlers()
{
    add_read_handler("stats", read_handler, H_STATS);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(SR2LinkTableMulti)
EXPORT_ELEMENT(SR2ForwarderMulti)
