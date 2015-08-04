/*
 * availablerates.{cc,hh} -- Poor man's arp table
 * John Bicket
 *
 * Copyright (c) 2003 Massachusetts Institute of Technology
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
#include <clicknet/ether.h>
#include "availableinterfaces.hh"
CLICK_DECLS

AvailableInterfaces::AvailableInterfaces()
{

  /* bleh */
  static unsigned char bcast_addr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  _bcast = EtherAddress(bcast_addr);

}

AvailableInterfaces::~AvailableInterfaces()
{
}

void *
AvailableInterfaces::cast(const char *n)
{
  if (strcmp(n, "AvailableInterfaces") == 0)
    return (AvailableInterfaces *) this;
  else
    return 0;
}

int
AvailableInterfaces::parse_and_insert(String s, ErrorHandler *errh)
{
  EtherAddress e_from;
  EtherAddress e_to;
  int r;
  int loc = 0;
  Vector<int> rates;
  Vector<String> args;
  cp_spacevec(s, args);
  if (args.size() < 4) {
    return errh->error("error param %s must have > 3 arg", s.c_str());
  }

  if (args[0] == "DEFAULT") {
	
	int iface;
  String iface_name;
  
	Vector<int> if_rates;
	if (!cp_integer(args[1], &r))
      return errh->error("error param %s: argument 1 should be an interface id (integer!)", s.c_str());
  iface = r;

  if (!cp_string(args[2], &iface_name))
      return errh->error("error param %s: argument 2 should be an interface name (string!)", s.c_str());

	if (!cp_ethernet_address(args[3], &e_from))
      return errh->error("error param %s: argument 3 should be an ethernet address", s.c_str());

	for (int x = 4; x< args.size(); x++) {
		if (!cp_integer(args[x], &r))
	      return errh->error("error param %s: argument %d should be a rate (integer!)", s.c_str(), x);
		  if_rates.push_back(r);
	}


	
	LocalIfInfo li = LocalIfInfo();
		li._eth = e_from;
	  li._iface = iface;
	  li._available = true;
	  li._rates = if_rates;
		li._iface_name = iface_name;
	  _default_ifaces.insert(iface, li);

				
	  return 0;
	
  } else {
	
    if (!cp_ethernet_address(args[0], &e_from))
      return errh->error("error param %s: argument 1 should be an ethernet address", s.c_str());

	if (!cp_ethernet_address(args[1], &e_to)) {

		if (!cp_integer(args[1], &r))
		return errh->error("error param %s: argument 2 should be an ethernet address", s.c_str());

		loc = 1;

	} else {

		loc = 0;

	}

	for (int x = 2-loc; x< args.size(); x++) {
		if (!cp_integer(args[x], &r))
	      return errh->error("error param %s: argument %d should be a rate (integer!)", s.c_str(), x);
		  rates.push_back(r);
	}

	if (loc == 1) {
		e_to = e_from;
	}

	EtherPair epair = EtherPair (e_from,e_to);
	DstInfo d = DstInfo(e_to);
	d._rates = rates;
	d._eth = e_to;
	_rtable.insert(epair, d);
	return 0;
	
  }

}
int
AvailableInterfaces::configure(Vector<String> &conf, ErrorHandler *errh)
{
  int res = 0;
  _debug = false;
  for (int x = 0; x < conf.size(); x++) {
    res = parse_and_insert(conf[x], errh);
    if (res != 0) {
      return res;
    }
  }
  
  return res;

}

int
AvailableInterfaces::initialize (ErrorHandler *)
{
  _timer.initialize (this);
  _timer.schedule_now ();

  return 0;
}

void
AvailableInterfaces::run_timer (Timer *)
{
  clean_wtable();
  Timestamp delay = Timestamp::make_msec(15000);
  _timer.schedule_at(Timestamp::now() + delay);
}

void
AvailableInterfaces::take_state(Element *e, ErrorHandler *)
{
  AvailableInterfaces *q = (AvailableInterfaces *)e->cast("AvailableInterfaces");
  if (!q) return;
  _rtable = q->_rtable;
  _default_ifaces = _default_ifaces;

}

Vector<int>
AvailableInterfaces::lookup(EtherPair epair)
{
  if (!epair._eth_from || !epair._eth_to) {
    click_chatter("%s: lookup called with NULL eth!\n", name().c_str());
    return Vector<int>();
  }

  DstInfo *dst = _rtable.findp(epair);
  if (dst) {
    return dst->_rates;
  }

  if (_default_ifaces.size()) {
	int iface = lookup_id(epair._eth_from);
	LocalIfInfo *ifinfo = _default_ifaces.findp(iface);
    if (ifinfo) {
    	return ifinfo->_rates;
  	}
  }

  return Vector<int>();
}

EtherAddress
AvailableInterfaces::lookup_if(int iface)
{
  if (!iface) {
    click_chatter("%s: lookup called with NULL iface!\n", name().c_str());
    return EtherAddress();
  }

  LocalIfInfo ifinfo = *(_default_ifaces.findp(iface));
  EtherAddress eth = ifinfo._eth;

  return eth;
}

EtherAddress
AvailableInterfaces::lookup_def()
{
    EtherAddress eth;
    LocalIfInfo ifinfo;

    for (IIter it = _default_ifaces.begin(); it.live(); it++){
		  ifinfo = it.value();
  		if (ifinfo._iface>=256 && ifinfo._iface<=511){
            eth = ifinfo._eth;
  		}
	  }
    
    return eth;
	
}

int
AvailableInterfaces::lookup_def_id()
{
    LocalIfInfo ifinfo;

    for (IIter it = _default_ifaces.begin(); it.live(); it++){
		  ifinfo = it.value();
  		if (ifinfo._iface>=256 && ifinfo._iface<=511){
            return ifinfo._iface;
  		}
	  }
    
    return 0;
	
}

int
AvailableInterfaces::lookup_id(EtherAddress eth)
{
	
	uint16_t if_id = 0;
	LocalIfInfo ifinfo;
	
	for (IIter it = _default_ifaces.begin(); it.live(); it++){
		ifinfo = it.value();
		if (ifinfo._eth==eth){
			if_id = it.key();
		}
	}
	
	return if_id;
	
}

bool
AvailableInterfaces::check_if_local(EtherAddress eth)
{
	
	bool is_local_if = false;
	LocalIfInfo ifinfo;
	
	for (IIter it = _default_ifaces.begin(); it.live(); it++){
		ifinfo = it.value();
		if (ifinfo._eth==eth){
			is_local_if = true;
		}
	}
	
	return is_local_if;
	
}

bool
AvailableInterfaces::check_if_present(int iface)
{
	
	bool present = false;
	LocalIfInfo ifinfo;
	
	for (IIter it = _default_ifaces.begin(); it.live(); it++){
		ifinfo = it.value();
		if (ifinfo._iface==iface){
			present = true;
		}
	}
	
	return present;
	
}

bool
AvailableInterfaces::check_if_available(int iface)
{
	
	LocalIfInfo *ifinfo = _default_ifaces.findp(iface);
	return ifinfo->_available;
	
}

bool
AvailableInterfaces::check_remote_available(EtherAddress eth)
{
  ChangingChannel *ccinfo = _wtable.findp(eth);
  
  if (!ccinfo){
    return true;
  } else {
    return false;
  }
  
}

String
AvailableInterfaces::get_if_name(int iface)
{
	
  LocalIfInfo ifinfo = *(_default_ifaces.findp(iface));
  String iface_name = ifinfo._iface_name;
	
	return iface_name;
  
}

void
AvailableInterfaces::set_available(int iface)
{
  
    LocalIfInfo *ifinfo = _default_ifaces.findp(iface);
    ifinfo->set_available();
	
}

void
AvailableInterfaces::set_unavailable(int iface)
{
  
	LocalIfInfo *ifinfo = _default_ifaces.findp(iface);
    ifinfo->set_unavailable();
	
}

void
AvailableInterfaces::clean_wtable(){
  
  WarnTable new_table;
  Timestamp now = Timestamp::now();
  for(WIter iter = _wtable.begin(); iter.live(); iter++) {
    ChangingChannel cchannel = iter.value();
    Timestamp expire = cchannel._last_update + Timestamp::make_msec(10000);  
    if (now < expire) {
      new_table.insert(iter.key(), cchannel);
    }
  }
  _wtable.clear();
  for(WIter iter = new_table.begin(); iter.live(); iter++) {
    ChangingChannel cchannel = iter.value();
    _wtable.insert(iter.key(), cchannel);
  }
  
  _timer.schedule_at(Timestamp::now() + Timestamp::make_msec(30000));
  
}

void
AvailableInterfaces::set_remote_unavailable(EtherAddress eth, bool status, ChangingChannel cchannel)
{
  
  ChangingChannel *ccinfo = _wtable.findp(eth);
  
  if (status){
    if (!ccinfo){
      cchannel._last_update = Timestamp::now();
      _wtable.insert(eth,cchannel);
      ccinfo = _wtable.findp(eth);
    } else {
      ccinfo->_host = cchannel._host;
      ccinfo->_iface_old = cchannel._iface_old;
      ccinfo->_iface_new = cchannel._iface_new;
      ccinfo->_last_update = Timestamp::now();
    }
    
  } else {
    if (!ccinfo){
      return;
    } else {
      _wtable.remove(eth);
    }
  }
  
}

void
AvailableInterfaces::set_channel_change(int old_iface, int new_iface)
{
  
  LocalIfInfo *ifinfo = _default_ifaces.findp(old_iface);
  
  ifinfo->_switch_to=new_iface;
  
}

int
AvailableInterfaces::check_channel_change(int iface)
{
  
  LocalIfInfo *ifinfo = _default_ifaces.findp(iface);
  
  int switch_to = ifinfo->_switch_to;
  
  return switch_to;
  
}

void
AvailableInterfaces::change_if(int old_iface, int new_iface)
{
  
  LocalIfInfo *ifinfo = _default_ifaces.findp(old_iface);
  
  LocalIfInfo li = LocalIfInfo();
  
	//li = *ifinfo;

  li._iface = new_iface;
  li._available = false;
  li._eth = ifinfo->_eth;
  li._rates = ifinfo->_rates;
  li._iface_name = ifinfo->_iface_name;
  
  _default_ifaces.remove(old_iface);
  _default_ifaces.insert(new_iface, li);
	
}

Vector<int>
AvailableInterfaces::get_local_rates(int iface)
{
	LocalIfInfo ifinfo;
	Vector<int> rates;
	
	for (IIter it = _default_ifaces.begin(); it.live(); it++){
		ifinfo = it.value();
		if (ifinfo._iface==iface){
			rates=ifinfo._rates;
		}
	}
	
	return rates;
}

HashMap<EtherAddress,AvailableInterfaces::LocalIfInfo>
AvailableInterfaces::get_if_list()
{
	LocalIfInfo ifinfo;
	
	HashMap<EtherAddress,AvailableInterfaces::LocalIfInfo> if_list;
	for (IIter it = _default_ifaces.begin(); it.live(); it++){
		ifinfo = it.value();
		if_list.insert(ifinfo._eth,ifinfo);
	}
	return if_list;
}

int
AvailableInterfaces::insert(EtherPair epair, Vector<int> rates)
{
  if (!epair._eth_from || !epair._eth_to) {
    if (_debug) {
      click_chatter("AvailableRates %s: You fool, you tried to insert %s and %s\n",
		    name().c_str(),
		    epair._eth_from.unparse().c_str(),
			epair._eth_to.unparse().c_str());
    }
    return -1;
  }
  DstInfo *dst = _rtable.findp(epair);
  if (!dst) {
    _rtable.insert(epair, DstInfo(epair._eth_to));
    dst = _rtable.findp(epair);
  }
  dst->_eth = epair._eth_to;
  dst->_rates.clear();
  int iface = lookup_id(epair._eth_from);
  LocalIfInfo ifinfo = *(_default_ifaces.findp(iface));
  Vector<int> _default_rates = ifinfo._rates;
  if (_default_ifaces.size()) {
    /* only add rates that are in the default rates */
    for (int x = 0; x < rates.size(); x++) {
      for (int y = 0; y < _default_rates.size(); y++) {
		if (rates[x] == _default_rates[y]) {
	  		dst->_rates.push_back(rates[x]);
		}
      }
    }
  } else {
    dst->_rates = rates;
  }
  return 0;
}





enum {H_DEBUG, H_INSERT, H_REMOVE, H_RATES, H_INTERFACES};


static String
AvailableInterfaces_read_param(Element *e, void *thunk)
{
  AvailableInterfaces *td = (AvailableInterfaces *)e;
  switch ((uintptr_t) thunk) {
  case H_DEBUG:
    return String(td->_debug) + "\n";
  case H_RATES: {
	AvailableInterfaces::DstInfo dstinfo;
	EtherPair ethp;
    StringAccum sa;
    if (td->_rtable.size()) {
			for (AvailableInterfaces::RIter it = td->_rtable.begin(); it.live(); it++){
				ethp = it.key();
				dstinfo = it.value();
				sa << ethp._eth_from.unparse() << " " << ethp._eth_to.unparse() << " ";
				for (int x=0; x<dstinfo._rates.size(); x++){
					sa << " " << dstinfo._rates[x];
				}
				sa << "\n";
			}

    }
    return sa.take_string();
  }
  case H_INTERFACES: {
	AvailableInterfaces::LocalIfInfo ifinfo;
    StringAccum sa;
    if (td->_default_ifaces.size()) {
			for (AvailableInterfaces::IIter it = td->_default_ifaces.begin(); it.live(); it++){
				sa << "INTERFACE ";
				ifinfo = it.value();
				sa << ifinfo._iface << " " << ifinfo._eth.unparse();
				for (int x=0; x<ifinfo._rates.size(); x++){
					sa << " " << ifinfo._rates[x];
				}
				sa << "\n";
			}
      
    }
    return sa.take_string();
  }
  default:
    return String();
  }
}
static int
AvailableInterfaces_write_param(const String &in_s, Element *e, void *vparam,
		      ErrorHandler *errh)
{
  AvailableInterfaces *f = (AvailableInterfaces *)e;
  String s = cp_uncomment(in_s);
  switch((intptr_t)vparam) {
  case H_DEBUG: {
    bool debug;
    if (!cp_bool(s, &debug))
      return errh->error("debug parameter must be boolean");
    f->_debug = debug;
    break;
  }
  case H_INSERT:
    return f->parse_and_insert(in_s, errh);
  case H_REMOVE: {
    EtherPair e;
    if (!cp_ethernet_address(s, &e._eth_from) && !cp_ethernet_address(s, &e._eth_to))
      return errh->error("remove parameter must be ethernet pair");
    f->_rtable.erase(e);
    break;
  }

  }
  return 0;
}

void
AvailableInterfaces::add_handlers()
{
  add_read_handler("debug", AvailableInterfaces_read_param, (void *) H_DEBUG);
  add_read_handler("rates", AvailableInterfaces_read_param, (void *) H_RATES);
  add_read_handler("interfaces", AvailableInterfaces_read_param, (void *) H_INTERFACES);


  add_write_handler("debug", AvailableInterfaces_write_param, (void *) H_DEBUG);
  add_write_handler("insert", AvailableInterfaces_write_param, (void *) H_INSERT);
  add_write_handler("remove", AvailableInterfaces_write_param, (void *) H_REMOVE);


}



CLICK_ENDDECLS
EXPORT_ELEMENT(AvailableInterfaces)

