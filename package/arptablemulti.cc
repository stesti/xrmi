/*
 * arptable.{cc,hh} -- ARP resolver element
 * Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2005 Regents of the University of California
 * Copyright (c) 2008 Meraki, Inc.
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
//#include "arpquerier.hh"
#include "arptablemulti.hh"
#include <clicknet/ether.h>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
#include <click/confparse.hh>
#include <click/bitvector.hh>
#include <click/straccum.hh>
#include <click/router.hh>
#include <click/error.hh>
#include <click/glue.hh>
CLICK_DECLS

ARPTableMulti::ARPTableMulti()
    : _entry_capacity(0), _packet_capacity(2048),
      _expire_jiffies(300 * CLICK_HZ), _expire_timer(this)
{
    _entry_count = _packet_count = _drops = 0;
}

ARPTableMulti::~ARPTableMulti()
{
}

int
ARPTableMulti::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Timestamp timeout(300);
    if (cp_va_kparse(conf, this, errh,
		     "CAPACITY", 0, cpUnsigned, &_packet_capacity,
		     "ENTRY_CAPACITY", 0, cpUnsigned, &_entry_capacity,
		     "TIMEOUT", 0, cpTimestamp, &timeout,
		     cpEnd) < 0)
	return -1;
    set_timeout(timeout);
    if (_expire_jiffies) {
	_expire_timer.initialize(this);
	_expire_timer.schedule_after_sec(_expire_jiffies / CLICK_HZ);
    }
    return 0;
}

void
ARPTableMulti::cleanup(CleanupStage)
{
    clear();
}

void
ARPTableMulti::clear()
{
    // Walk the arp cache table and free any stored packets and arp entries.
    for (Table::iterator it = _table.begin(); it; ) {
	ARPEntryMulti *ae = _table.erase(it);
	while (Packet *p = ae->_head) {
	    ae->_head = p->next();
	    p->kill();
	    ++_drops;
	}
	_alloc.deallocate(ae);
    }
    _entry_count = _packet_count = 0;
    _age.__clear();
}

void
ARPTableMulti::take_state(Element *e, ErrorHandler *errh)
{
    ARPTableMulti *arpt = (ARPTableMulti *)e->cast("ARPTableMulti");
    if (!arpt)
	return;
    if (_table.size() > 0) {
	errh->error("late take_state");
	return;
    }

    _table.swap(arpt->_table);
    _age.swap(arpt->_age);
    _entry_count = arpt->_entry_count;
    _packet_count = arpt->_packet_count;
    _drops = arpt->_drops;
    _alloc.swap(arpt->_alloc);

    arpt->_entry_count = 0;
    arpt->_packet_count = 0;
}

void
ARPTableMulti::slim()
{
    click_jiffies_t now = click_jiffies();
    ARPEntryMulti *ae;

    // Delete old entries.
    while ((ae = _age.front())
	   && (ae->expired(now, _expire_jiffies)
	       || (_entry_capacity && _entry_count > _entry_capacity))) {
	_table.erase(ae->_node);
	_age.pop_front();

	while (Packet *p = ae->_head) {
	    ae->_head = p->next();
	    p->kill();
	    --_packet_count;
	    ++_drops;
	}

	_alloc.deallocate(ae);
	--_entry_count;
    }

    // Mark entries for polling, and delete packets to make space.
    while (_packet_capacity && _packet_count > _packet_capacity) {
	while (ae->_head && _packet_count > _packet_capacity) {
	    Packet *p = ae->_head;
	    if (!(ae->_head = p->next()))
		ae->_tail = 0;
	    p->kill();
	    --_packet_count;
	    ++_drops;
	}
	ae = ae->_age_link.next();
    }
}

void
ARPTableMulti::run_timer(Timer *timer)
{
    // Expire any old entries, and make sure there's room for at least one
    // packet.
    _lock.acquire_write();
    slim();
    _lock.release_write();
    if (_expire_jiffies)
	timer->schedule_after_sec(_expire_jiffies / CLICK_HZ + 1);
}

ARPTableMulti::ARPEntryMulti *
ARPTableMulti::ensure(NodeAddress node)
{
    _lock.acquire_write();
    Table::iterator it = _table.find(node);
    if (!it) {
	void *x = _alloc.allocate();
	if (!x) {
	    _lock.release_write();
	    return 0;
	}

	++_entry_count;
	if (_entry_capacity && _entry_count > _entry_capacity)
	    slim();

	ARPEntryMulti *ae = new(x) ARPEntryMulti(node);
	ae->_live_jiffies = click_jiffies();
	ae->_poll_jiffies = ae->_live_jiffies - CLICK_HZ;
	_table.set(it, ae);

	_age.push_back(ae);
    }
    return it.get();
}

int
ARPTableMulti::insert(NodeAddress node, const EtherAddress &eth, Packet **head)
{
    ARPEntryMulti *ae = ensure(node);
    if (!ae)
	return -ENOMEM;

    ae->_eth = eth;
    ae->_unicast = !eth.is_broadcast();

    ae->_live_jiffies = click_jiffies();
    ae->_poll_jiffies = ae->_live_jiffies - CLICK_HZ;

    if (ae->_age_link.next()) {
	_age.erase(ae);
	_age.push_back(ae);
    }

    if (head) {
	*head = ae->_head;
	ae->_head = ae->_tail = 0;
	for (Packet *p = *head; p; p = p->next())
	    --_packet_count;
    }

    _table.balance();
    _lock.release_write();
    return 0;
}

void
ARPTableMulti::change_if(NodeAddress node, uint16_t new_iface)
{

	  _lock.acquire_write();
    Table::iterator it = _table.find(node);

		NodeAddress node_new = NodeAddress(node._ipaddr,new_iface);
		
		if (it) {
			
			ARPEntryMulti *ae = it.get();	
			ae->_node._iface=new_iface;

		} else {
			
			click_chatter("%{element}: Can't find %s-%d to change into %d\n",
						this,
						node._ipaddr.unparse().c_str(),
						node._iface,
						new_iface);
			
		}
		
		_lock.release_write();
	
}

int
ARPTableMulti::append_query(NodeAddress node, Packet *p)
{
    ARPEntryMulti *ae = ensure(node);
    if (!ae)
	return -ENOMEM;

    click_jiffies_t now = click_jiffies();
    if (ae->unicast(now, _expire_jiffies)) {
	_lock.release_write();
	return -EAGAIN;
    }

    ++_packet_count;
    if (_packet_capacity && _packet_count > _packet_capacity)
	slim();

    if (ae->_tail)
	ae->_tail->set_next(p);
    else
	ae->_head = p;
    ae->_tail = p;
    p->set_next(0);

    int r;
    if (!click_jiffies_less(now, ae->_poll_jiffies + CLICK_HZ / 10)) {
	ae->_poll_jiffies = now;
	r = 1;
    } else
	r = 0;

    _table.balance();
    _lock.release_write();
    return r;
}

NodeAddress
ARPTableMulti::reverse_lookup(const EtherAddress &eth)
{
    _lock.acquire_read();

    NodeAddress node;
    for (Table::iterator it = _table.begin(); it; ++it){
			if (it->_eth == eth) {
			    node = it->_node;
			    break;
			}
		}

    _lock.release_read();
    return node;
}

EtherAddress
ARPTableMulti::lookup_def_eth(const EtherAddress &eth)
{
    
    _lock.acquire_read();

    bool found = false;
    NodeAddress node;
    EtherAddress eth_out;
    
    for (Table::iterator it = _table.begin(); it; ++it) {
	    if (it->_eth == eth) {
	      node = it->_node;
	      break;
	    }
		}
	    
    for (Table::iterator it = _table.begin(); it; ++it) {
	    if (it->_node._ipaddr == node._ipaddr) {
	      if ((it->_node._iface >= 256) && (it->_node._iface <= 511)) {
	        eth_out = it->_eth;
          found = true;
	        break;
        }
	    }
		}

    _lock.release_read();
    
    if (!found){
      eth_out = EtherAddress::make_broadcast();
    }
    
    return eth_out;
}

EtherAddress
ARPTableMulti::lookup_def(NodeAddress node)
{
    
    _lock.acquire_read();

    bool found = false;
    EtherAddress eth_out;
	    
    for (Table::iterator it = _table.begin(); it; ++it) {
	    if (it->_node._ipaddr == node._ipaddr) {
	      if ((it->_node._iface >= 256) && (it->_node._iface <= 511)) {
	        eth_out = it->_eth;
          found = true;
	        break;
        }
	    }
		}

    _lock.release_read();
    
    if (!found){
      eth_out = EtherAddress::make_broadcast();
    }
    
    return eth_out;
}

String
ARPTableMulti::read_handler(Element *e, void *user_data)
{
    ARPTableMulti *arpt = (ARPTableMulti *) e;
    StringAccum sa;
    click_jiffies_t now = click_jiffies();
    switch (reinterpret_cast<uintptr_t>(user_data)) {
      case h_table:
	for (Table::const_iterator it = arpt->_table.begin(); it; ++it) {
	    int ok = it->unicast(now, arpt->_expire_jiffies);
	    sa << it->_node._ipaddr << ' ' << it->_node._iface << ' ' << ok << ' ' << it->_eth << ' '
	       << Timestamp::make_jiffies(now - it->_live_jiffies) << '\n';
	}
	break;
    }
    return sa.take_string();
}

int
ARPTableMulti::write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh)
{
    ARPTableMulti *arpt = (ARPTableMulti *) e;
    switch (reinterpret_cast<uintptr_t>(user_data)) {
      case h_insert: {
	  NodeAddress node;
	  EtherAddress eth;
	  if (!cp_va_space_kparse(str, arpt, errh,
				  "IP", cpkP+cpkM, cpIPAddress, &node._ipaddr,
				// add handler for node
				  "ETH", cpkP+cpkM, cpEtherAddress, &eth,
				  cpEnd) < 0)
	      return -1;
	  arpt->insert(node, eth);
	  return 0;
      }
      case h_delete: {
	  NodeAddress node;
	  if (!cp_va_space_kparse(str, arpt, errh,
				  "IP", cpkP+cpkM, cpIPAddress, &node._ipaddr,
				// add handler for node
				  cpEnd) < 0)
	      return -1;
	  arpt->insert(node, EtherAddress::make_broadcast()); // XXX?
	  return 0;
      }
      case h_clear:
	arpt->clear();
	return 0;
      default:
	return -1;
    }
}

void
ARPTableMulti::add_handlers()
{
    add_read_handler("table", read_handler, h_table);
    add_data_handlers("drops", Handler::OP_READ, &_drops);
    add_write_handler("insert", write_handler, h_insert);
    add_write_handler("delete", write_handler, h_delete);
    add_write_handler("clear", write_handler, h_clear);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ARPTableMulti)
ELEMENT_MT_SAFE(ARPTableMulti)
