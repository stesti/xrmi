/*
 * SR2LinkTableMulti.{cc,hh} -- Routing Table in terms of links
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
#include "sr2linktablemulti.hh"
#include "sr2nodemulti.hh"
#include "sr2pathmulti.hh"

CLICK_DECLS

SR2LinkTableMulti::SR2LinkTableMulti()
  : _timer(this)
{
}


SR2LinkTableMulti::~SR2LinkTableMulti()
{
}


int
SR2LinkTableMulti::initialize (ErrorHandler *)
{
  _timer.initialize(this);
  _timer.schedule_now();
  return 0;
}


void
SR2LinkTableMulti::run_timer(Timer *)
{
  clear_stale();
  dijkstra(true);
  dijkstra(false);
  _timer.schedule_after_msec(5000);
}


void *
SR2LinkTableMulti::cast(const char *n)
{
  if (strcmp(n, "SR2LinkTableMulti") == 0)
    return (SR2LinkTableMulti *) this;
  else
    return 0;
}


int
SR2LinkTableMulti::configure (Vector<String> &conf, ErrorHandler *errh)
{
  int ret;
  int stale_period = 120;
  ret = cp_va_kparse(conf, this, errh,
		     "IP", 0, cpIPAddress, &_ip,		
		     "STALE", 0, cpUnsigned, &stale_period,
		     cpEnd);

  if (!_ip)
    return errh->error("IP not specified");

  _stale_timeout.assign(stale_period, 0);
  _hosts.insert(_ip, SR2HostInfoMulti(_ip));
  return ret;
}


void
SR2LinkTableMulti::take_state(Element *e, ErrorHandler *) {
  SR2LinkTableMulti *q = (SR2LinkTableMulti *)e->cast("SR2LinkTableMulti");
  if (!q) return;

  _hosts = q->_hosts;
  _links = q->_links;
  dijkstra(true);
  dijkstra(false);
}

int
SR2LinkTableMulti::static_update_link(const String &arg, Element *e,
			      void *, ErrorHandler *errh)
{
  SR2LinkTableMulti *n = (SR2LinkTableMulti *) e;
  Vector<String> args;
  NodeAddress from;
  NodeAddress to;
  uint32_t seq;
  uint32_t age;
  uint32_t metric;
  cp_spacevec(arg, args);

  if (args.size() != 5) {
    return errh->error("Must have three arguments: currently has %d: %s", args.size(), args[0].c_str());
  }


// Give a look here:

//  if (!cp_ip_address(args[0]._ipaddr, &from)) {
//    return errh->error("Couldn't read IPAddress out of from");
//  }

// Add here the checking code that can check the interface
// of type uint16_t

// Give a look here:

//  if (!cp_ip_address(args[1]._ipaddr, &to)) {
//    return errh->error("Couldn't read IPAddress out of to");
//  }

// Add here the checking code that can check the interface
// of type uint16_t

  if (!cp_unsigned(args[2], &metric)) {
    return errh->error("Couldn't read metric");
  }

  if (!cp_unsigned(args[3], &seq)) {
    return errh->error("Couldn't read seq");
  }

  if (!cp_unsigned(args[4], &age)) {
    return errh->error("Couldn't read age");
  }

  n->update_link(from, to, seq, age, metric);
  return 0;

}


void
SR2LinkTableMulti::clear()
{
  _hosts.clear();
  _links.clear();

}


bool
SR2LinkTableMulti::update_link(NodeAddress from, NodeAddress to,
		       uint32_t seq, uint32_t age, uint32_t metric)
{
  if (!from || !to || !metric) {
    return false;
  }
  if (_stale_timeout.sec() < (int) age) {
    return true;
  }

  /* make sure both the hosts exist */
  SR2HostInfoMulti *nfrom = _hosts.findp(from._ipaddr);
  if (!nfrom) {
    SR2HostInfoMulti foo = SR2HostInfoMulti(from._ipaddr);
    _hosts.insert(from._ipaddr, foo);
    nfrom = _hosts.findp(from._ipaddr);
  }
  SR2HostInfoMulti *nto = _hosts.findp(to._ipaddr);
  if (!nto) {
    _hosts.insert(to._ipaddr, SR2HostInfoMulti(to._ipaddr));
    nto = _hosts.findp(to._ipaddr);
  }

  nfrom->new_interface(from._iface);
  nto->new_interface(to._iface);

  assert(nfrom);
  assert(nto);

  NodePair p = NodePair(from, to);
  SR2LinkInfoMulti *lnfo = _links.findp(p);
  if (!lnfo) {
    _links.insert(p, SR2LinkInfoMulti(from, to, seq, age, metric));
  } else {
    lnfo->update(seq, age, metric);
  }
  return true;
}

SR2LinkTableMulti::SR2LinkMulti
SR2LinkTableMulti::random_link()
{
  int ndx = click_random(0, _links.size() - 1);
  int current_ndx = 0;
  for (SR2LTIterMulti iter = _links.begin(); iter.live(); iter++, current_ndx++) {
    if (current_ndx == ndx) {
      SR2LinkInfoMulti n = iter.value();
      return SR2LinkMulti(n._from, n._to, n._seq, n._metric);
    }
  }
  click_chatter("SR2LinkTableMulti %s: random_link overestimated number of elements\n",
		name().c_str());
  return SR2LinkMulti();

}

Vector<IPAddress>
SR2LinkTableMulti::get_hosts()
{
  Vector<IPAddress> v;
  for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++) {
    SR2HostInfoMulti n = iter.value();
    v.push_back(n._ip);
  }
  return v;
}


uint32_t
SR2LinkTableMulti::get_host_metric_to_me(IPAddress s)
{
  if (!s) {
    return 0;
  }
  SR2HostInfoMulti *nfo = _hosts.findp(s);
  if (!nfo) {
    return 0;
  }
  return nfo->_metric_to_me;
}


uint32_t
SR2LinkTableMulti::get_host_metric_from_me(IPAddress s)
{
  if (!s) {
    return 0;
  }
  SR2HostInfoMulti *nfo = _hosts.findp(s);
  if (!nfo) {
    return 0;
  }
  return nfo->_metric_from_me;
}


uint32_t
SR2LinkTableMulti::get_link_metric(NodeAddress from, NodeAddress to)
{
  if (!from || !to) {
    return 0;
  }
  if (_blacklist.findp(from._ipaddr) || _blacklist.findp(to._ipaddr)) {
    return 0;
  }
  NodePair p = NodePair(from, to);
  SR2LinkInfoMulti *nfo = _links.findp(p);
  if (!nfo) {
    return 0;
  }
  return nfo->_metric;
}


uint32_t
SR2LinkTableMulti::get_link_seq(NodeAddress from, NodeAddress to)
{
  if (!from || !to) {
    return 0;
  }
  if (_blacklist.findp(from._ipaddr) || _blacklist.findp(to._ipaddr)) {
    return 0;
  }
  NodePair p = NodePair(from, to);
  SR2LinkInfoMulti *nfo = _links.findp(p);
  if (!nfo) {
    return 0;
  }
  return nfo->_seq;
}


uint32_t
SR2LinkTableMulti::get_link_age(NodeAddress from, NodeAddress to)
{
  if (!from || !to) {
    return 0;
  }
  if (_blacklist.findp(from._ipaddr) || _blacklist.findp(to._ipaddr)) {
    return 0;
  }
  NodePair p = NodePair(from, to);
  SR2LinkInfoMulti *nfo = _links.findp(p);
  if (!nfo) {
    return 0;
  }
  return nfo->age();
}

uint16_t
SR2LinkTableMulti::get_if_def(IPAddress node)
{
	if (!node) {
    return 0;
  }
  if (_blacklist.findp(node)) {
    return 0;
  }
  SR2HostInfoMulti *nfo = _hosts.findp(node);
  if (!nfo) {
    return 0;
  }
  return nfo->_if_def;
}

uint32_t
SR2LinkTableMulti::get_link_rate(NodeAddress from, NodeAddress to)
{
  if (!from || !to) {
    return 0;
  }
  if (_blacklist.findp(from._ipaddr) || _blacklist.findp(to._ipaddr)) {
    return 0;
  }
  NodePair p = NodePair(from, to);
  SR2LinkInfoMulti *nfo = _links.findp(p);
  if (!nfo) {
    return 0;
  }
  return nfo->_rate;
}

void
SR2LinkTableMulti::set_link_rate(NodeAddress from, NodeAddress to, uint32_t rate)
{
  if (!from || !to || !rate) {
    return;
  }
  if (_blacklist.findp(from._ipaddr) || _blacklist.findp(to._ipaddr)) {
    return;
  }
  NodePair p = NodePair(from, to);
  SR2LinkInfoMulti *nfo = _links.findp(p);
  if (!nfo) {
    return;
  }
  nfo->_rate = rate;
}


uint32_t
SR2LinkTableMulti::get_link_retries(NodeAddress from, NodeAddress to)
{
  if (!from || !to) {
    return 0;
  }
  if (_blacklist.findp(from._ipaddr) || _blacklist.findp(to._ipaddr)) {
    return 0;
  }
  NodePair p = NodePair(from, to);
  SR2LinkInfoMulti *nfo = _links.findp(p);
  if (!nfo) {
    return 0;
  }
  return nfo->_retries;
}


void
SR2LinkTableMulti::set_link_retries(NodeAddress from, NodeAddress to, uint32_t retries)
{
  if (!from || !to || !retries) {
    return;
  }
  if (_blacklist.findp(from._ipaddr) || _blacklist.findp(to._ipaddr)) {
    return;
  }
  NodePair p = NodePair(from, to);
  SR2LinkInfoMulti *nfo = _links.findp(p);
  if (!nfo) {
    return;
  }
  nfo->_retries = retries;
}


uint32_t
SR2LinkTableMulti::get_link_probe(NodeAddress from, NodeAddress to)
{
  if (!from || !to) {
    return 0;
  }
  if (_blacklist.findp(from._ipaddr) || _blacklist.findp(to._ipaddr)) {
    return 0;
  }
  NodePair p = NodePair(from, to);
  SR2LinkInfoMulti *nfo = _links.findp(p);
  if (!nfo) {
    return 0;
  }
  return nfo->_probe;
}


void
SR2LinkTableMulti::set_link_probe(NodeAddress from, NodeAddress to, uint32_t probe)
{
  if (!from || !to || !probe) {
    return;
  }
  if (_blacklist.findp(from._ipaddr) || _blacklist.findp(to._ipaddr)) {
    return;
  }
  NodePair p = NodePair(from, to);
  SR2LinkInfoMulti *nfo = _links.findp(p);
  if (!nfo) {
    return;
  }
  nfo->_probe = probe;
}

void
SR2LinkTableMulti::change_if(NodeAddress node, uint16_t new_iface){
	
	for (SR2LTIterMulti iter = _links.begin(); iter.live(); iter++) {
		NodePair nodep = iter.key();
	}
	for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++) {
		SR2HostInfoMulti hinfo = iter.value();
	}
	
	for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++) {

		SR2HostInfoMulti hinfo = iter.value();
		SR2PathMulti best = best_route(iter.key(), true);
		
		for (int i=0; i < best.size(); i++) {
			NodeAirport tmp = best[i];
	  }
			
	}
	
	Vector<NodePair> link_remove;
	Vector<SR2HostInfoMulti> host_remove;
	
	for (SR2LTIterMulti iter = _links.begin(); iter.live(); iter++) {
    if ((iter.key()._from == node) || (iter.key()._to == node)){
			link_remove.push_back(iter.key());
		}
  }

	for (int i=0; i< link_remove.size(); i++) {
		NodePair nodep = link_remove[i];
		_links.remove(link_remove[i]);
	}

	link_remove.clear();

	for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++) {

		SR2HostInfoMulti hinfo = iter.value();
		bool changed = false;
		
		if (((iter.key() == node._ipaddr) && (hinfo._if_from_me == node._iface)) || (hinfo._prev_from_me == node)) {
			hinfo._if_from_me = hinfo._if_def;
			hinfo._prev_from_me._iface = get_if_def(hinfo._prev_from_me._ipaddr);
			changed=true;
		}
		if (((iter.key() == node._ipaddr) && (hinfo._if_to_me == node._iface)) || (hinfo._prev_to_me == node)) {
			hinfo._if_to_me = hinfo._if_def;
			hinfo._prev_to_me._iface = get_if_def(hinfo._prev_to_me._ipaddr);
			changed=true;
		}
		
		if (changed){
			hinfo.update_interface(node._iface,new_iface);
			host_remove.push_back(hinfo);
		}
			
	}
	
	for (int i=0; i < host_remove.size(); i++){
		SR2HostInfoMulti hinfo = host_remove[i];
		_hosts.remove(hinfo._ip);
		_hosts.insert(hinfo._ip,hinfo);
	}
	
	host_remove.clear();
	
	for (SR2LTIterMulti iter = _links.begin(); iter.live(); iter++) {
		NodePair nodep = iter.key();
	}
	for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++) {
		SR2HostInfoMulti hinfo = iter.value();
	}

	//dijkstra(true);
  //dijkstra(false);

	for (SR2LTIterMulti iter = _links.begin(); iter.live(); iter++) {
		NodePair nodep = iter.key();
	}
	for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++) {
		SR2HostInfoMulti hinfo = iter.value();
	}

	for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++) {

		SR2HostInfoMulti hinfo = iter.value();
		SR2PathMulti best = best_route(iter.key(), true);
		
		for (int i=0; i < best.size(); i++) {
			NodeAirport tmp = best[i];
	  }
			
	}

}


unsigned
SR2LinkTableMulti::get_route_metric(const Vector<NodeAirport> &route)
{
  unsigned metric = 0;
  for (int i = 0; i < route.size() - 1; i++) {
    NodeAddress nfrom = NodeAddress(route[i]._ipaddr, route[i]._dep_iface);
    NodeAddress nto = NodeAddress(route[i+1]._ipaddr, route[i+1]._arr_iface);
    unsigned m = get_link_metric(nfrom,nto);
    if (m == 0) {
      return 0;
    }
    metric += m;
  }
  return metric;

}


String
SR2LinkTableMulti::route_to_string(SR2PathMulti p) {
	StringAccum sa;
	int hops = p.size()-1;
	int metric = 0;
	StringAccum sa2;
	for (int i = 0; i < p.size(); i++) {
		sa2 << p[i]._ipaddr << "," << p[i]._arr_iface << "," << p[i]._dep_iface;
		if (i != p.size()-1) {
			NodeAddress nfrom = NodeAddress(p[i]._ipaddr, p[i]._dep_iface);
			NodeAddress nto = NodeAddress(p[i+1]._ipaddr, p[i+1]._arr_iface);
			int m = get_link_metric(nfrom,nto);
			sa2 << " (" << m << ") ";
			metric += m;
		}
	}
	sa << p[p.size()-1]._ipaddr << " hops " << hops << " metric " << metric << " " << sa2;
	return sa.take_string();
}


bool
SR2LinkTableMulti::valid_route(const Vector<NodeAirport> &route)
{
  if (route.size() < 1) {
    return false;
  }
  /* ensure the metrics are all valid */
  unsigned metric = get_route_metric(route);
  if (metric  == 0 ||
      metric >= 777777){
    return false;
  }

  /* ensure that a node appears no more than once */
  for (int x = 0; x < route.size(); x++) {
    for (int y = x + 1; y < route.size(); y++) {
      if (route[x]._ipaddr == route[y]._ipaddr) {
	return false;
      }
    }
  }
  //click_chatter("Route is valid!\n");
  return true;
}


Vector<NodeAirport>
SR2LinkTableMulti::best_route(IPAddress dst, bool from_me)
{
  Vector<NodeAirport> reverse_route;
  if (!dst) {
    return reverse_route;
  }
  SR2HostInfoMulti *nfo = _hosts.findp(dst);
  uint16_t prev_if = 0;

  if (from_me) {
    while (nfo && nfo->_metric_from_me != 0) {
      reverse_route.push_back(NodeAirport(nfo->_ip,nfo->_if_from_me,prev_if));
      prev_if = nfo->_prev_from_me._iface;
      nfo = _hosts.findp(nfo->_prev_from_me._ipaddr);
    }
    if (nfo && nfo->_metric_from_me == 0) {
    reverse_route.push_back(NodeAirport(nfo->_ip,0,prev_if));
    }
  } else {
    while (nfo && nfo->_metric_to_me != 0) {
      reverse_route.push_back(NodeAirport(nfo->_ip,prev_if,nfo->_if_to_me));
      prev_if = nfo->_prev_to_me._iface;
      nfo = _hosts.findp(nfo->_prev_to_me._ipaddr);
    }
    if (nfo && nfo->_metric_to_me == 0) {
      reverse_route.push_back(NodeAirport(nfo->_ip,prev_if,0));
    }
  }


  if (from_me) {
	  Vector<NodeAirport> route;
	  /* why isn't there just push? */
	  for (int i=reverse_route.size() - 1; i >= 0; i--) {
		  route.push_back(reverse_route[i]);
	  }
	  return route;
  }

  return reverse_route;
}

static int ipaddr_sorter(const void *va, const void *vb, void *) {
    IPAddress *a = (IPAddress *)va, *b = (IPAddress *)vb;
    if (a->addr() == b->addr()) {
	return 0;
    }
    return (ntohl(a->addr()) < ntohl(b->addr())) ? -1 : 1;
}


String
SR2LinkTableMulti::print_routes(bool from_me, bool pretty)
{
  StringAccum sa;

  Vector<IPAddress> ip_addrs;

  for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++)
    ip_addrs.push_back(iter.key());

  click_qsort(ip_addrs.begin(), ip_addrs.size(), sizeof(IPAddress), ipaddr_sorter);

  for (int x = 0; x < ip_addrs.size(); x++) {
    IPAddress ip = ip_addrs[x];
    Vector<NodeAirport> r = best_route(ip, from_me);
    if (valid_route(r)) {
	    if (pretty) {
		    sa << route_to_string(r) << "\n";
	    } else {
		    sa << r[r.size()-1]._ipaddr << "  ";
		    for (int a = 0; a < r.size(); a++) {
			    sa << r[a]._ipaddr << "," << r[a]._arr_iface << "," << r[a]._dep_iface;
			    if (a < r.size() - 1) {
				    NodeAddress nfrom = NodeAddress(r[a]._ipaddr, r[a]._dep_iface);
				    NodeAddress nto = NodeAddress(r[a+1]._ipaddr, r[a+1]._arr_iface);
				    sa << " " << get_link_metric(nfrom, nto);
				    sa << " (" << get_link_seq(nfrom, nto)
				       << "," << get_link_age(nfrom, nto)
				       << ") ";
			    }
		    }
		    sa << "\n";
	    }
    }
  }
  return sa.take_string();
}


String
SR2LinkTableMulti::print_links()
{
  StringAccum sa;
  for (SR2LTIterMulti iter = _links.begin(); iter.live(); iter++) {
    SR2LinkInfoMulti n = iter.value();
    sa << n._from._ipaddr.unparse() << "," << n._from._iface << " - " << n._to._ipaddr.unparse() << "," << n._to._iface;
    sa << " " << n._metric;
    sa << " " << n._rate;
    sa << " " << n._seq << " " << n.age() << "\n";
  }
  return sa.take_string();
}


String
SR2LinkTableMulti::print_hosts()
{
  StringAccum sa;
  Vector<IPAddress> ip_addrs;

  for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++)
    ip_addrs.push_back(iter.key());

  click_qsort(ip_addrs.begin(), ip_addrs.size(), sizeof(IPAddress), ipaddr_sorter);

  for (int x = 0; x < ip_addrs.size(); x++){
		SR2HostInfoMulti * hnfo = _hosts.findp(ip_addrs[x]);
		sa << ip_addrs[x] << " interfaces:";
		for (int y=0; y < hnfo->_interfaces.size(); y++) {
			sa << " " << hnfo->_interfaces[y];
		}
		sa << "\n";
	}
    

  return sa.take_string();
}



void
SR2LinkTableMulti::clear_stale() {

  SR2LTableMulti links;
  for (SR2LTIterMulti iter = _links.begin(); iter.live(); iter++) {
    SR2LinkInfoMulti nfo = iter.value();
    if ((unsigned) _stale_timeout.sec() >= nfo.age()) {
      links.insert(NodePair(nfo._from, nfo._to), nfo);
    } else {
      if (0) {
	click_chatter("%{element} :: %s removing link %s -> %s metric %d seq %d age %d\n",
		      this,
		      __func__,
		      nfo._from._ipaddr.unparse().c_str(),
		      nfo._from._iface,
		      nfo._to._ipaddr.unparse().c_str(),
		      nfo._to._iface,
		      nfo._metric,
		      nfo._seq,
		      nfo.age());
      }
    }
  }
  _links.clear();

  for (SR2LTIterMulti iter = links.begin(); iter.live(); iter++) {
    SR2LinkInfoMulti nfo = iter.value();
    _links.insert(NodePair(nfo._from, nfo._to), nfo);
  }

}


Vector<IPAddress>
SR2LinkTableMulti::get_neighbors(IPAddress ip)
{
  Vector<IPAddress> neighbors;

  typedef HashMap<IPAddress, bool> IPMap;
  IPMap ip_addrs;

  for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++) {
    ip_addrs.insert(iter.value()._ip, true);
  }

  SR2HostInfoMulti *current = _hosts.findp(ip);

  for (IPMap::const_iterator i = ip_addrs.begin(); i.live(); i++) {
	
    SR2HostInfoMulti *neighbor = _hosts.findp(i.key());

    if (ip != neighbor->_ip) {
      SR2LinkInfoMulti *lnfo = 0;
      for(int i_ifa = 0; i_ifa < current->_interfaces.size(); i_ifa++) {
				for(int i_ifb = 0; i_ifb < neighbor->_interfaces.size(); i_ifb++) {
					lnfo = _links.findp(NodePair(NodeAddress(ip,current->_interfaces[i_ifa]), NodeAddress(neighbor->_ip,neighbor->_interfaces[i_ifb])));
				}
    	}
      if (lnfo) {
				neighbors.push_back(neighbor->_ip);
      }
    }

  }

  return neighbors;
}

HashMap<NodeAddress,int>
SR2LinkTableMulti::get_neighbors_if(int iface)
{
  HashMap<NodeAddress,int> neighbors;

  typedef HashMap<IPAddress, bool> IPMap;
  IPMap ip_addrs;

  for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++) {
    ip_addrs.insert(iter.value()._ip, true);
  }

	NodeAddress node = NodeAddress(_ip,iface);

  for (IPMap::const_iterator i = ip_addrs.begin(); i.live(); i++) {
	
    SR2HostInfoMulti *neighbor = _hosts.findp(i.key());

    if (_ip != neighbor->_ip) {
      SR2LinkInfoMulti *lnfo = 0;
			for(int i_ifb = 0; i_ifb < neighbor->_interfaces.size(); i_ifb++) {
				lnfo = _links.findp(NodePair(node, NodeAddress(neighbor->_ip,neighbor->_interfaces[i_ifb])));
				if (lnfo) {
					neighbors.insert(NodeAddress(neighbor->_ip,neighbor->_interfaces[i_ifb]),neighbor->_metric_from_me);
	      }
			}
    }

  }

  return neighbors;
}


void
SR2LinkTableMulti::dijkstra(bool from_me)
{
  Timestamp start = Timestamp::now();
  IPAddress src = _ip;

  typedef HashMap<IPAddress, bool> IPMap;
  IPMap ip_addrs;

  typedef HashMap<uint16_t, bool> IFMap;

  for (SR2HTIterMulti iter = _hosts.begin(); iter.live(); iter++) {
    ip_addrs.insert(iter.value()._ip, true);
  }

  for (IPMap::const_iterator iter = ip_addrs.begin(); iter.live(); iter++) {
    /* clear them all initially */
    SR2HostInfoMulti *n = _hosts.findp(iter.key());
    n->clear(from_me);
  }
  SR2HostInfoMulti *root_info = _hosts.findp(src);


  assert(root_info);

  if (from_me) {
    root_info->_prev_from_me = NodeAddress(root_info->_ip,0);
    root_info->_metric_from_me = 0;
  } else {
    root_info->_prev_to_me = NodeAddress(root_info->_ip,0);
    root_info->_metric_to_me = 0;
  }

  IPAddress current_min_ip = root_info->_ip;

  while (current_min_ip) {
    SR2HostInfoMulti *current_min = _hosts.findp(current_min_ip);
    assert(current_min);

		if (from_me) {
		  current_min->_marked_from_me = true;
		} else {
		  current_min->_marked_to_me = true;
		}

		for (int i_ifcur = 0; i_ifcur < current_min->_interfaces.size(); i_ifcur++){
			for (IPMap::const_iterator i = ip_addrs.begin(); i.live(); i++) {
			  SR2HostInfoMulti *neighbor = _hosts.findp(i.key());
			  for(int i_ifnei = 0; (i_ifnei < neighbor->_interfaces.size()) && (current_min_ip != i.key()); i_ifnei++){
				  
					assert(neighbor);
				  bool marked = neighbor->_marked_to_me;
				  if (from_me) {
					marked = neighbor->_marked_from_me;
				  }

				  if (marked) {
					continue;
				  }

				  NodePair pair = NodePair(NodeAddress(neighbor->_ip,neighbor->_interfaces[i_ifnei]), NodeAddress(current_min_ip,current_min->_interfaces[i_ifcur]));
				  if (from_me) {
					pair = NodePair(NodeAddress(current_min_ip,current_min->_interfaces[i_ifcur]), NodeAddress(neighbor->_ip,neighbor->_interfaces[i_ifnei]));
				  }
				  SR2LinkInfoMulti *lnfo = _links.findp(pair);
				  if (!lnfo || !lnfo->_metric) {
					continue;
				  }
				  uint32_t neighbor_metric = neighbor->_metric_to_me;
				  uint32_t current_metric = current_min->_metric_to_me;

				  if (from_me) {
					neighbor_metric = neighbor->_metric_from_me;
					current_metric = current_min->_metric_from_me;
				  }

					// For ETT
				  // uint32_t adjusted_metric = current_metric + lnfo->_metric;
					// End ETT
				
					// For WCETT
				
					uint32_t max_metric = 0;
					uint32_t total_ett = lnfo->_metric;
					uint32_t link_channel = neighbor->_interfaces[i_ifnei] % 256;
					bool ch_found = false;
					MetricTable * metric_table;
				
					if (from_me) {
						metric_table = &(current_min->_metric_table_from_me);
					} else {
						metric_table = &(current_min->_metric_table_to_me);
					}
				
					for (MetricIter it_metric = metric_table->begin(); it_metric.live(); it_metric++) {
						uint32_t actual_metric = 0;
						if (it_metric.key() == link_channel) {
							ch_found = true;
							actual_metric = it_metric.value() + lnfo->_metric;
						} else {
							actual_metric = it_metric.value();
						}

						if (actual_metric > max_metric) {
							max_metric = actual_metric;
						}

						total_ett = total_ett + it_metric.value();

					}
				
					if ((!ch_found) && (lnfo->_metric > max_metric)) {
						max_metric = lnfo->_metric;
					}
				
				  uint32_t adjusted_metric = total_ett + max_metric;

				// End WCETT
			
				  if (!neighbor_metric ||
				  adjusted_metric < neighbor_metric) {
					if (from_me) {
					  neighbor->_metric_from_me = adjusted_metric;
					  neighbor->_prev_from_me = NodeAddress(current_min_ip,current_min->_interfaces[i_ifcur]);
					  neighbor->_if_from_me = neighbor->_interfaces[i_ifnei];
						// WCETT support
						neighbor->_metric_table_from_me.clear();
						for (MetricIter it_metric = current_min->_metric_table_from_me.begin(); it_metric.live(); it_metric++) {
							neighbor->_metric_table_from_me.insert(it_metric.key(),it_metric.value());
						}
						uint32_t* ch_metric = neighbor->_metric_table_from_me.findp(link_channel);
						if (!ch_metric){
							neighbor->_metric_table_from_me.insert(link_channel,lnfo->_metric);
						} else {
							*ch_metric = *ch_metric + lnfo->_metric;
						}
						// End WCETT
					} else {
					  neighbor->_metric_to_me = adjusted_metric;
					  neighbor->_prev_to_me = NodeAddress(current_min_ip,current_min->_interfaces[i_ifcur]);
					  neighbor->_if_to_me = neighbor->_interfaces[i_ifnei];
						// WCETT support
						neighbor->_metric_table_to_me.clear();
						for (MetricIter it_metric = current_min->_metric_table_to_me.begin(); it_metric.live(); it_metric++) {
							neighbor->_metric_table_to_me.insert(it_metric.key(),it_metric.value());
						}
						uint32_t* ch_metric = neighbor->_metric_table_to_me.findp(link_channel);
						if (!ch_metric){
							neighbor->_metric_table_to_me.insert(link_channel,lnfo->_metric);
						} else {
							*ch_metric = *ch_metric + lnfo->_metric;
						}
						// End WCETT
					}

			  }
			}
		}

	}

		current_min_ip = IPAddress();
		uint32_t  min_metric = ~0;
		for (IPMap::const_iterator i = ip_addrs.begin(); i.live(); i++) {
		  SR2HostInfoMulti *nfo = _hosts.findp(i.key());
		  uint32_t metric = nfo->_metric_to_me;
		  bool marked = nfo->_marked_to_me;
		  if (from_me) {
			metric = nfo->_metric_from_me;
			marked = nfo->_marked_from_me;
		  }
		  if (!marked && metric &&
		  metric < min_metric) {
		    current_min_ip = nfo->_ip;
		    min_metric = metric;
		  }
		}

  }

  dijkstra_time = Timestamp::now() - start;
  //StringAccum sa;
  //sa << "dijstra took " << finish - start;
  //click_chatter("%s: %s\n", name().c_str(), sa.take_string().c_str());
}


enum {H_BLACKLIST,
      H_BLACKLIST_CLEAR,
      H_BLACKLIST_ADD,
      H_BLACKLIST_REMOVE,
      H_LINKS,
      H_ROUTES_OLD,
      H_ROUTES_FROM,
      H_ROUTES_TO,
      H_HOSTS,
      H_CLEAR,
      H_DIJKSTRA,
      H_DIJKSTRA_TIME};

static String
SR2LinkTableMulti_read_param(Element *e, void *thunk)
{
  SR2LinkTableMulti *td = (SR2LinkTableMulti *)e;
    switch ((uintptr_t) thunk) {
    case H_BLACKLIST: {
      StringAccum sa;
      typedef HashMap<IPAddress, IPAddress> IPTable;
      typedef IPTable::const_iterator IPIter;


      for (IPIter iter = td->_blacklist.begin(); iter.live(); iter++) {
	sa << iter.value() << " ";
      }
      return sa.take_string() + "\n";
    }
    case H_LINKS:  return td->print_links();
    case H_ROUTES_TO: return td->print_routes(false, true);
    case H_ROUTES_FROM: return td->print_routes(true, true);
    case H_ROUTES_OLD: return td->print_routes(true, false);
    case H_HOSTS:  return td->print_hosts();
    case H_DIJKSTRA_TIME: {
      StringAccum sa;
      sa << td->dijkstra_time << "\n";
      return sa.take_string();
    }
    default:
      return String();
    }
}
static int
SR2LinkTableMulti_write_param(const String &in_s, Element *e, void *vparam,
		      ErrorHandler *errh)
{
  SR2LinkTableMulti *f = (SR2LinkTableMulti *)e;
  String s = cp_uncomment(in_s);
  switch((intptr_t)vparam) {
  case H_BLACKLIST_CLEAR: {
    f->_blacklist.clear();
    break;
  }
  case H_BLACKLIST_ADD: {
    IPAddress m;
    if (!cp_ip_address(s, &m))
      return errh->error("blacklist_add parameter must be ipaddress");
    f->_blacklist.insert(m, m);
    break;
  }
  case H_BLACKLIST_REMOVE: {
    IPAddress m;
    if (!cp_ip_address(s, &m))
      return errh->error("blacklist_add parameter must be ipaddress");
    f->_blacklist.erase(m);
    break;
  }
  case H_CLEAR: f->clear(); break;
  case H_DIJKSTRA: f->dijkstra(true); f->dijkstra(false); break;
  }
  return 0;
}


void
SR2LinkTableMulti::add_handlers() {
  add_read_handler("routes", SR2LinkTableMulti_read_param, (void *)H_ROUTES_FROM);
  add_read_handler("routes_old", SR2LinkTableMulti_read_param, (void *)H_ROUTES_OLD);
  add_read_handler("routes_from", SR2LinkTableMulti_read_param, (void *)H_ROUTES_FROM);
  add_read_handler("routes_to", SR2LinkTableMulti_read_param, (void *)H_ROUTES_TO);
  add_read_handler("links", SR2LinkTableMulti_read_param, (void *)H_LINKS);
  add_read_handler("hosts", SR2LinkTableMulti_read_param, (void *)H_HOSTS);
  add_read_handler("blacklist", SR2LinkTableMulti_read_param, (void *)H_BLACKLIST);
  add_read_handler("dijkstra_time", SR2LinkTableMulti_read_param, (void *)H_DIJKSTRA_TIME);

  add_write_handler("clear", SR2LinkTableMulti_write_param, (void *)H_CLEAR);
  add_write_handler("blacklist_clear", SR2LinkTableMulti_write_param, (void *)H_BLACKLIST_CLEAR);
  add_write_handler("blacklist_add", SR2LinkTableMulti_write_param, (void *)H_BLACKLIST_ADD);
  add_write_handler("blacklist_remove", SR2LinkTableMulti_write_param, (void *)H_BLACKLIST_REMOVE);
  add_write_handler("dijkstra", SR2LinkTableMulti_write_param, (void *)H_DIJKSTRA);


  add_write_handler("update_link", static_update_link, 0);


}

EXPORT_ELEMENT(SR2LinkTableMulti)
CLICK_ENDDECLS
