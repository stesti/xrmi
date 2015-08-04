/*
 * sr2ettmetric.{cc,hh} -- estimated transmission count (`ETT') metric
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
 * legally binding.  */

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include "sr2ettmetricmulti.hh"
#include "sr2txcountmetricmulti.hh"
#include "sr2ettstatmulti.hh"
#include "sr2linktablemulti.hh"
#include "sr2nodemulti.hh"
CLICK_DECLS 

SR2ETTMetricMulti::SR2ETTMetricMulti()
  : SR2LinkMetricMulti()
{
}

SR2ETTMetricMulti::~SR2ETTMetricMulti()
{
}

void *
SR2ETTMetricMulti::cast(const char *n) 
{
  if (strcmp(n, "SR2ETTMetricMulti") == 0)
    return (SR2LinkTableMulti *) this;
  else if (strcmp(n, "SR2LinkMetricMulti") == 0)
    return (SR2LinkTableMulti *) this;
  else
    return 0;
}

void
SR2ETTMetricMulti::update_link(NodeAddress from, NodeAddress to, 
		       Vector<SR2RateSize> rs, 
		       Vector<int> fwd, Vector<int> rev, 
		       uint32_t seq)
{

  if (!from || !to) {
    click_chatter("%{element} :: %s :: called with %s %s\n",
		  this,
		  __func__,
		  from._ipaddr.unparse().c_str(),
		  from._iface,
		  to._ipaddr.unparse().c_str(),
		  to._iface);
    return;
  }

  int one_ack_fwd = 0;
  int one_ack_rev = 0;
  int six_ack_fwd = 0;
  int six_ack_rev = 0;

  /* 
   * if we don't have a few probes going out, just pick
   * the smallest size for fwd rate
   */
  int one_ack_size = 0;
  int six_ack_size = 0;

  for (int x = 0; x < rs.size(); x++) {
    if (rs[x]._rate == 2 && 
	(!one_ack_size ||
	 one_ack_size > rs[x]._size)) {
      one_ack_size = rs[x]._size;
      one_ack_fwd = fwd[x];
      one_ack_rev = rev[x];
    } else if (rs[x]._rate == 12 && 
	       (!six_ack_size ||
		six_ack_size > rs[x]._size)) {
      six_ack_size = rs[x]._size;
      six_ack_fwd = fwd[x];
      six_ack_rev = rev[x];
    }
  }
    
  if (!one_ack_fwd && !six_ack_fwd &&
      !one_ack_rev && !six_ack_rev) {
    return;
  }

  int rev_metric = 0;
  int fwd_metric = 0;

  int rev_rate = 0;
  int fwd_rate = 0;
  
  int rev_retries = 0;
  int fwd_retries = 0;

  int rev_probe = 0;
  int fwd_probe = 0;
  
  for (int x = 0; x < rs.size(); x++) {
    if (rs[x]._size >= 100) {
      int ack_fwd = 0;
      int ack_rev = 0;
      if ((rs[x]._rate == 2) ||
	  (rs[x]._rate == 4) ||
	  (rs[x]._rate == 11) ||
	  (rs[x]._rate == 22)) {
	ack_fwd = one_ack_fwd;
	ack_rev = one_ack_rev;
      } else {
	ack_fwd = six_ack_fwd;
	ack_rev = six_ack_rev;
      }

      int metric = sr2_ett_metric(ack_rev, fwd[x], rs[x]._rate);
      int retries = sr2_etx_metric(ack_rev, fwd[x]);

      if (!fwd_metric|| (metric && metric < fwd_metric)) {
	fwd_probe = rs[x]._size;
	fwd_rate = rs[x]._rate;
	fwd_metric = metric;
	fwd_retries = retries;
      }
      
      metric = sr2_ett_metric(ack_fwd, rev[x], rs[x]._rate);
      retries = sr2_etx_metric(ack_rev, fwd[x]);

      if (!rev_metric || (metric && metric < rev_metric)) {
	rev_probe = rs[x]._size;
	rev_rate= rs[x]._rate;
	rev_metric = metric;
	rev_retries = retries;
      }
    }
  }

  /* update linktable */
  if (fwd_metric && 
      _link_table && 
      !_link_table->update_link(from, to, seq, 0, fwd_metric)) {

    _link_table->set_link_rate(from, to, fwd_rate);
    _link_table->set_link_probe(from, to, fwd_probe);
    _link_table->set_link_retries(from, to, fwd_retries);

  }
  if (rev_metric && 
      _link_table && 
      !_link_table->update_link(to, from, seq, 0, rev_metric)){

    _link_table->set_link_rate(from, to, rev_rate);
    _link_table->set_link_probe(from, to, rev_probe);
    _link_table->set_link_retries(from, to, rev_retries);

  }
}

EXPORT_ELEMENT(SR2ETTMetricMulti)
ELEMENT_REQUIRES(bitrate)
ELEMENT_REQUIRES(SR2LinkMetricMulti)
ELEMENT_REQUIRES(SR2TXCountMetricMulti)
CLICK_ENDDECLS
