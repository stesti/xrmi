/*
 * John Bicket
 *
 * Copyright (c) 1999-2003 Massachusetts Institute of Technology
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
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <clicknet/ether.h>
#include <elements/wifi/availablerates.hh>
#include "arptablemulti.hh"
#include "availableinterfaces.hh"
#include "sr2ettstatmulti.hh"
#include "sr2packetmulti.hh"
#include "sr2linkmetricmulti.hh"
CLICK_DECLS

enum { H_RESET, H_BCAST_STATS, H_IP, H_TAU, H_PERIOD, H_PROBES };

SR2ETTStatMulti::SR2ETTStatMulti()
  : _ads_rs_index(0),
    _tau(10000), 
    _period(1000), 
    _sent(0),
    _link_metric(0),
    _arp_table(0),
    _if_table(0),
    _timer(this)
{
}

SR2ETTStatMulti::~SR2ETTStatMulti()
{
}

void
SR2ETTStatMulti::run_timer(Timer *)
{

  int p = _period / _ads_rs.size();
  unsigned max_jitter = p / 10;
  if (_if_table->check_if_available(_if_table->lookup_id(_eth))) {
			if (_iface != _if_table->lookup_id(_eth)) {
				_iface = _if_table->lookup_id(_eth);
				reset();
			}
      send_probe();
  }
  unsigned j = click_random(0, 2 * max_jitter);
  unsigned delay = p + j - max_jitter;
  _timer.reschedule_after_msec(delay);
}

int
SR2ETTStatMulti::initialize(ErrorHandler *)
{

	_iface = _if_table->lookup_id(_eth);
  if (noutputs() > 0) {
    int p = _period / _ads_rs.size();
    unsigned max_jitter = p / 10;
    unsigned j = click_random(0, 2 * max_jitter);
    _timer.initialize(this);    
    _timer.reschedule_after_msec(p + j - max_jitter);
  }
  reset();
  return 0;
}

int
SR2ETTStatMulti::configure(Vector<String> &conf, ErrorHandler *errh)
{
  String probes;
  int res = cp_va_kparse(conf, this, errh,
			 "ETHTYPE", 0, cpUnsignedShort, &_et,
			 "IP", 0, cpIPAddress, &_ip,
			 "ETH", 0, cpEtherAddress, &_eth,
		     "IT", 0, cpElement, &_if_table,
			 "PERIOD", 0, cpUnsigned, &_period,
			 "TAU", 0, cpUnsigned, &_tau,
			 "METRIC", 0, cpElement, &_link_metric,
			 "ARP", 0, cpElement, &_arp_table,
			 "PROBES", 0, cpString, &probes,
			 cpEnd);

  if ((res = write_handler(probes, this, (void *) H_PROBES, errh)) < 0) {
    return res;
  }
  if (!_et) {
    return errh->error("Must specify ETHTYPE");
  }
  if (!_ip) {
    return errh->error("Invalid IPAddress specified\n");
  }
  if (!_eth) {
    return errh->error("Invalid EtherAddress specified\n");
  }
  if (_link_metric && _link_metric->cast("SR2LinkMetricMulti") == 0) {
    return errh->error("METRIC element is not a SR2LinkMetricMulti");
  }
  if (_arp_table && _arp_table->cast("ARPTableMulti") == 0) {
    return errh->error("ARPTableMulti element is not a ARPTableMulti");
  }
  if (_if_table && _if_table->cast("AvailableInterfaces") == 0) 
    return errh->error("AvailableInterfaces element is not an AvailableInterfaces");
  return res;
}

void
SR2ETTStatMulti::send_probe() 
{
  if (!_ads_rs.size()) {
    click_chatter("%{element} :: %s :: no probes to send at", this, __func__);
    return;
  }

	Vector<EtherAddress> neighbors_remove;

  int size = _ads_rs[_ads_rs_index]._size;
  int rate = _ads_rs[_ads_rs_index]._rate;

  _ads_rs_index = (_ads_rs_index + 1) % _ads_rs.size();
  _sent++;
  unsigned min_packet_size = (sizeof(click_ether) + sizeof(struct link_probe_multi))/2;
  if ((unsigned) size < min_packet_size) {
    click_chatter("%{element} :: %s :: cannot send packet size %d: min is %d",
		  this, 
		  __func__,
		  size,
		  min_packet_size);
    return;
  }

  WritablePacket *p = Packet::make(size + sizeof(click_ether)); 
  if (!p) {
    click_chatter("%{element} :: %s :: cannot make packet!", this, __func__);
    return;
  }

  memset(p->data(), 0, p->length());

  click_ether *eh = (click_ether *) p->data();
  eh->ether_type = htons(_et);
  memset(eh->ether_dhost, 0xff, 6); 
  memcpy(eh->ether_shost, _eth.data(), 6);
  link_probe_multi *lp = (struct link_probe_multi *) (p->data() + sizeof(click_ether));
  lp->_version = _sr2_version;
  lp->_type = SR2_PT_PROBE;
	int my_iface = _if_table->lookup_id(_eth);
  lp->set_node(NodeAddress(_ip,my_iface));
  lp->set_seq(Timestamp::now().sec());
  lp->set_period(_period);
  lp->set_tau(_tau);
  lp->set_sent(_sent);
  lp->unset_flag(~0);
  lp->set_rate(rate);
  lp->set_size(size);
  lp->set_num_probes(_ads_rs.size());

  uint8_t *ptr =  (uint8_t *) (lp + 1);
  uint8_t *end  = (uint8_t *) p->data() + p->length();

  // rate_entry
  Vector<int> rates;
  if (_if_table) {
		int my_iface = _if_table->lookup_id(_eth);
    rates = _if_table->get_local_rates(my_iface);
  }
  if (rates.size() && ptr + sizeof(rate_entry) * rates.size() < end) {
    for (int x = 0; x < rates.size(); x++) {
        rate_entry *r_entry = (struct rate_entry *)(ptr); 
        r_entry->set_rate(rates[x]);
        ptr += sizeof(rate_entry);
    }
    lp->set_flag(PROBE_AVAILABLE_RATES);
    lp->set_num_rates(rates.size());
  } 

  int num_entries = 0;

  while (ptr < end && num_entries < _neighbors.size()) {

    _neighbors_index = (_neighbors_index + 1) % _neighbors.size();

    if (_neighbors_index >= _neighbors.size()) {
      break;
    }

		//NodeAddress current_neighbor = _arp_table->reverse_lookup(_neighbors[_neighbors_index]);
    ProbeListMulti *probe = _bcast_stats.findp(_neighbors[_neighbors_index]);

    if (!probe) {
      click_chatter("%{element} :: %s :: lookup for %s, %d failed in ad \n", 
		    this,
		    __func__,
		    _neighbors[_neighbors_index].unparse().c_str(),
		    _neighbors_index);
    } else {
	
			// Check for interface change
			NodeAddress node = _arp_table->reverse_lookup(_neighbors[_neighbors_index]);
			if (node._iface != probe->_node._iface) {

				neighbors_remove.push_back(_neighbors[_neighbors_index]);
				
				if ((_neighbors_index == 0) && (num_entries == 0)) {
					break;
				}
									
			} else {
				int size = probe->_probe_types.size()*sizeof(link_info) + sizeof(link_entry_multi);
	      if (ptr + size > end) {
					break;
	      }
	      num_entries++;
	      link_entry_multi *entry = (struct link_entry_multi *)(ptr);
	      entry->set_node(node);
	      entry->set_seq(probe->_seq);	
	      if (probe->_eth.unparse() > _eth.unparse()) {
					entry->set_seq(lp->seq());
	      }
	      entry->set_num_rates(probe->_probe_types.size());

	      ptr += sizeof(link_entry_multi);

	      Vector<SR2RateSize> rates;
	      Vector<int> fwd;
	      Vector<int> rev;

	      for (int x = 0; x < probe->_probe_types.size(); x++) {
					SR2RateSize rs = probe->_probe_types[x];
					link_info *lnfo = (struct link_info *) (ptr + x*sizeof(link_info));
					lnfo->set_size(rs._size);
					lnfo->set_rate(rs._rate);
					lnfo->set_fwd(probe->fwd_rate(rs._rate, rs._size));
					lnfo->set_rev(probe->rev_rate(_start, rs._rate, rs._size));
					rates.push_back(rs);
					fwd.push_back(lnfo->fwd());
					rev.push_back(lnfo->rev());
	      }
				int my_iface = _if_table->lookup_id(_eth);
				node = _arp_table->reverse_lookup(probe->_eth);
	      _link_metric->update_link(NodeAddress(_ip,my_iface), node, rates, fwd, rev, entry->seq());
	      ptr += probe->_probe_types.size()*sizeof(link_info);
	    }
		
		}

      
  }

	// Cleaning _bcast_stats table
	
	for (int i=0; i< neighbors_remove.size(); i++) {
		_bcast_stats.remove(neighbors_remove[i]);
	}
	
	// End of cleaning _bcast_stats table

	// Cleaning _neighbors table
	
	_neighbors.clear();
  for(ProbeIter iter = _bcast_stats.begin(); iter.live(); iter++) {
    _neighbors.push_back(iter.key());
  }
	
	// End of cleaning _neighbors table
	neighbors_remove.clear();

  lp->set_flag(PROBE_LINK_ENTRIES);
  lp->set_num_links(num_entries);
  lp->set_checksum();
  
  struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
  ceh->magic = WIFI_EXTRA_MAGIC;
  ceh->rate = rate;

  checked_output_push(0, p);
}

Packet *
SR2ETTStatMulti::simple_action(Packet *p)
{
  click_ether *eh = (click_ether *) p->data();
  struct link_probe_multi *lp = (struct link_probe_multi *) (eh+1);
  if (p->length() < sizeof(click_ether) + sizeof(struct sr2packetmulti)) {
    click_chatter("%{element} :: %s :: packet truncated", this, __func__);
    p->kill();
    return 0;
  }
  if (ntohs(eh->ether_type) != _et) {
    click_chatter("%{element} :: %s :: wrong packet type", this, __func__);
    p->kill();
    return 0;
  }
  if (lp->_version != _sr2_version) {
    click_chatter ("%{element} :: %s :: unknown protocol version %x from %s", 
		   this,	
		   __func__,
		   lp->_version,
		   EtherAddress(eh->ether_shost).unparse().c_str());
    p->kill();
    return 0;
  }
  if (eh->ether_type != htons(_et)) {
    click_chatter("%{element} :: %s :: bad ether_type %04x",
                       this,
                       __func__,
                       ntohs(eh->ether_type));
    p->kill();
    return 0;
  }
  if (!lp->check_checksum()) {
    click_chatter("%{element} :: %s :: failed checksum", this, __func__);
    p->kill();
    return 0;
  }
  if (p->length() < lp->size() + sizeof(click_ether)) {
    click_chatter("%{element} :: %s :: packet is smaller (%d) than it claims (%u)",
		  this,	
		  __func__,
		  p->length(),
		  lp->size());
    p->kill();
    return 0;
  }
  NodeAddress node = lp->node();
  if (node._ipaddr == _ip) {
    click_chatter("%{element} :: %s :: got own packet from %s-%d on interface %d\n",
		  this,
		  __func__,
		  _ip.unparse().c_str(),
			node._iface,
			_iface);
    p->kill();
    return 0;
  }
  if (_arp_table) {
    _arp_table->insert(node, EtherAddress(eh->ether_shost));
  }
  struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
  if (ceh->rate != lp->rate()) {
    click_chatter("%{element} :: %s :: packet says rate %d is %d\n",
		  this,
		  __func__,
		  lp->rate(),
		  ceh->rate);
    p->kill();
    return 0;
  }
  uint32_t new_period = lp->period();
  uint32_t tau = lp->tau();
  ProbeListMulti *probe_list = _bcast_stats.findp(EtherAddress(eh->ether_shost));
  if (!probe_list) {
    _bcast_stats.insert(EtherAddress(eh->ether_shost), ProbeListMulti(EtherAddress(eh->ether_shost), node, new_period, tau));
    probe_list = _bcast_stats.findp(EtherAddress(eh->ether_shost));
    probe_list->_sent = 0;
    _neighbors.push_back(EtherAddress(eh->ether_shost));
  } else if (node._iface != probe_list->_node._iface) {
	  click_chatter("%{element} :: %s :: %s,%d, has changed its interface %d to %d; clearing probe info",
		  this,
		  __func__,
		  node._ipaddr.unparse().c_str(), 
		  probe_list->_node._iface,
		  probe_list->_node._iface, 
		  node._iface);
			probe_list->_node._iface = node._iface;
			probe_list->_probes.clear();
	} else if (probe_list->_period != new_period) {
    click_chatter("%{element} :: %s :: %s,%d, has changed its link probe period from %u to %u; clearing probe info",
		  this,
		  __func__,
		  node._ipaddr.unparse().c_str(), 
		  node._iface,
		  probe_list->_period, 
		  new_period);
    probe_list->_probes.clear();
  } else if (probe_list->_tau != tau) {
    click_chatter("%{element} :: %s :: %s,%d, has changed its link probe period from %u to %u; clearing probe info",
		  this,
		  __func__,
		  node._ipaddr.unparse().c_str(), 
		  node._iface,
		  probe_list->_tau, 
		  tau);

    probe_list->_probes.clear();
  }
  if (lp->sent() < probe_list->_sent) {
    click_chatter("%{element} :: %s :: %s has reset; clearing probe info",
		  this,
		  __func__,
		  node._ipaddr.unparse().c_str());
    probe_list->_probes.clear();
  }
  Timestamp now = Timestamp::now();
  SR2RateSize rs = SR2RateSize(ceh->rate, lp->size());
  probe_list->_period = new_period;
  probe_list->_tau = lp->tau();
  probe_list->_sent = lp->sent();
  probe_list->_last_rx = now;
  probe_list->_num_probes = lp->num_probes();
  probe_list->_probes.push_back(Probe(now, lp->seq(), lp->rate(), lp->size(), ceh->rssi, ceh->silence));
  probe_list->_seq = lp->seq();
  uint32_t window = 1 + (probe_list->_tau / 1000);

  /* keep stats for at least the averaging period */
  while (probe_list->_probes.size() && 
	 now.sec() - probe_list->_probes[0]._when.sec() > (signed) window) {
    probe_list->_probes.pop_front();
  }

  int x = 0;
  for (x = 0; x < probe_list->_probe_types.size(); x++) {
    if (rs == probe_list->_probe_types[x]) {
      break;
    }
  }
  
  if (x == probe_list->_probe_types.size()) {
    probe_list->_probe_types.push_back(rs);
    probe_list->_fwd_rates.push_back(0);
  }

  uint8_t *ptr = (uint8_t *) (lp + 1);
  uint8_t *end = (uint8_t *) p->data() + p->length();

  if (lp->flag(PROBE_AVAILABLE_RATES)) {
    int num_rates = lp->num_rates();
    Vector<int> rates;
    for (int x = 0; x < num_rates; x++) {
        rate_entry *r_entry = (struct rate_entry *)(ptr); 
        rates.push_back(r_entry->rate());
        ptr += sizeof(rate_entry);
    }
    if(_if_table) {
      _if_table->insert(EtherPair(_eth,EtherAddress(eh->ether_shost)), rates);
    }
  }
  int link_number = 0;
  int num_links = lp->num_links();
  while (ptr < end && link_number < num_links) {
    link_number++;
    link_entry_multi *entry = (struct link_entry_multi *)(ptr); 
    NodeAddress neighbor = entry->node();
    uint32_t num_rates = entry->num_rates();
    ptr += sizeof(struct link_entry_multi);
    Vector<SR2RateSize> rates;
    Vector<int> fwd;
    Vector<int> rev;
    for (uint32_t x = 0; x < num_rates; x++) {
      struct link_info *nfo = (struct link_info *) (ptr + x * (sizeof(struct link_info)));
      uint16_t nfo_size = nfo->size();
      uint16_t nfo_rate = nfo->rate();
      uint16_t nfo_fwd = nfo->fwd();
      uint16_t nfo_rev = nfo->rev();
      
      SR2RateSize rs = SR2RateSize(nfo_rate, nfo_size);
      /* update other link stuff */
      rates.push_back(rs);
      fwd.push_back(nfo_fwd);
      if (neighbor._ipaddr == _ip) {
	rev.push_back(probe_list->rev_rate(_start, rates[x]._rate, rates[x]._size));
      } else {
	rev.push_back(nfo_rev);
      }

      if (neighbor._ipaddr == _ip) {
	/* set the fwd rate */
	for (int x = 0; x < probe_list->_probe_types.size(); x++) {
	  if (rs == probe_list->_probe_types[x]) {
	    probe_list->_fwd_rates[x] = nfo_rev;
	    break;
	  }
	}
      }
    }
    int seq = entry->seq();
    if (neighbor._ipaddr == node._ipaddr && ((uint32_t) neighbor._ipaddr > (uint32_t) _ip)) {
	seq = now.sec();
    }
    _link_metric->update_link(node, neighbor, rates, fwd, rev, seq);
    ptr += num_rates * sizeof(struct link_info);
  }
  p->kill();
  return 0;
}

void
SR2ETTStatMulti::reset()
{
  _neighbors.clear();
  _bcast_stats.clear();
  _seq = 0;
  _sent = 0;
  _start = Timestamp::now();
}
/*
static int nodeaddress_sorter(const void *va, const void *vb, void *) {
    NodeAddress *a = (NodeAddress *)va, *b = (NodeAddress *)vb;
    if ((a->_ipaddr == b->_ipaddr) && ((a->_iface == b->_iface))) {
      return 0;
    } 

    if ((a->_ipaddr == b->_ipaddr) && ((a->_iface < b->_iface))) {
      return -1;
    } else {
	    if ((a->_ipaddr == b->_ipaddr) && ((a->_iface > b->_iface))) {
	      return 1;
	    } else {
			return (ntohl(a->_ipaddr) < ntohl(b->_ipaddr)) ? -1 : 1;
		}
    }
}
*/

static int etheraddress_sorter(const void *va, const void *vb, void *) {

		EtherAddress *a = (EtherAddress *)va, *b = (EtherAddress *)vb;

		if (a==b){
			return 0;
		} else {
			return (a->unparse() < b->unparse()) ? -1 : 1;
		}

}

String
SR2ETTStatMulti::print_bcast_stats()
{
  Vector<EtherAddress> eth_addrs;
  
  for(ProbeIter iter = _bcast_stats.begin(); iter.live(); iter++) {
    eth_addrs.push_back(iter.key());
  }

  Timestamp now = Timestamp::now();
  StringAccum sa;
  click_qsort(eth_addrs.begin(), eth_addrs.size(), sizeof(EtherAddress), etheraddress_sorter);

  for (int i = 0; i < eth_addrs.size(); i++) {
    EtherAddress eth  = eth_addrs[i];
    ProbeListMulti *pl = _bcast_stats.findp(eth);
		sa << eth.unparse().c_str() << " " << pl->_node._ipaddr.unparse().c_str() << "-" << pl->_node._iface;

    sa << " seq " << pl->_seq;
    sa << " period " << pl->_period;
    sa << " tau " << pl->_tau;
    sa << " sent " << pl->_sent;
    sa << " last_rx " << now - pl->_last_rx;
    sa << "\n";

    for (int x = 0; x < _ads_rs.size(); x++) {
	    int rate = _ads_rs[x]._rate;
	    int size = _ads_rs[x]._size;
	    int rev = pl->rev_rate(_start, rate, size);
	    int fwd = pl->fwd_rate(rate, size);
	    int rssi = pl->rev_rssi(rate, size);
	    int noise = pl->rev_noise(rate, size);

    	sa << eth.unparse().c_str();

	    sa << " [ " << rate << " " << size << " ";
	    sa << fwd << " " << rev << " ";
	    sa << rssi << " " << noise << " ]";
	    sa << "\n";
    }
  }
  return sa.take_string();
}


String
SR2ETTStatMulti::read_handler(Element *e, void *thunk)
{
  SR2ETTStatMulti *td = (SR2ETTStatMulti *)e;
  switch ((uintptr_t) thunk) {
    case H_BCAST_STATS: 
      return td->print_bcast_stats();
    case H_IP: 
      return td->_ip.unparse() + "\n";
    case H_TAU: 
      return String(td->_tau) + "\n";
    case H_PERIOD: 
      return String(td->_period) + "\n";
    case H_PROBES: {
      StringAccum sa;
      for(int x = 0; x < td->_ads_rs.size(); x++) {
	sa << td->_ads_rs[x]._rate << " " << td->_ads_rs[x]._size << " ";
      }
      return sa.take_string() + "\n";
    }
    default:
      return String() + "\n";
    }
}

int 
SR2ETTStatMulti::write_handler(const String &in_s, Element *e, void *vparam,
		     ErrorHandler *errh)
{
  SR2ETTStatMulti *f = (SR2ETTStatMulti *)e;
  String s = cp_uncomment(in_s);
  switch((intptr_t)vparam) {
    case H_RESET: {
      f->reset();
      break;
    }
    case H_TAU: {
      unsigned m;
      if (!cp_unsigned(s, &m)) 
        return errh->error("tau parameter must be unsigned");
      f->_tau = m;
      f->reset();
    }
    case H_PERIOD: {
      unsigned m;
      if (!cp_unsigned(s, &m)) 
        return errh->error("period parameter must be unsigned");
      f->_period = m;
      f->reset();
    }
    case H_PROBES: {
      Vector<SR2RateSize> ads_rs;
      Vector<String> a;
      cp_spacevec(s, a);
      if (a.size() % 2 != 0) {
        return errh->error("must provide even number of numbers\n");
      }
      for (int x = 0; x < a.size() - 1; x += 2) {
        int rate;
        int size;
        if (!cp_integer(a[x], &rate)) {
          return errh->error("invalid PROBES rate value\n");
        }
        if (!cp_integer(a[x + 1], &size)) {
          return errh->error("invalid PROBES size value\n");
        }
        ads_rs.push_back(SR2RateSize(rate, size));
      }
      if (!ads_rs.size()) {
        return errh->error("no PROBES provided\n");
      }
      f->_ads_rs = ads_rs;
    }
  }
  return 0;
}

void
SR2ETTStatMulti::add_handlers()
{
  add_read_handler("bcast_stats", read_handler, (void *) H_BCAST_STATS);
  add_read_handler("ip", read_handler, (void *) H_IP);
  add_read_handler("tau", read_handler, (void *) H_TAU);
  add_read_handler("period", read_handler, (void *) H_PERIOD);
  add_read_handler("probes", read_handler, (void *) H_PROBES);

  add_write_handler("reset", write_handler, (void *) H_RESET);
  add_write_handler("tau", write_handler, (void *) H_TAU);
  add_write_handler("period", write_handler, (void *) H_PERIOD);
  add_write_handler("probes", write_handler, (void *) H_PROBES);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SR2ETTStatMulti)

