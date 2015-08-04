/*
 * sr2linkmetric.{cc,hh}
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
#include <click/straccum.hh>
#include "sr2linkmetricmulti.hh"
#include "sr2linktablemulti.hh"
#include "sr2nodemulti.hh"
CLICK_DECLS

SR2LinkMetricMulti::SR2LinkMetricMulti()
  : _link_table(0)
{
}

SR2LinkMetricMulti::~SR2LinkMetricMulti()
{
}

int
SR2LinkMetricMulti::configure(Vector<String> &conf, ErrorHandler *errh)
{
  int res = cp_va_kparse(conf, this, errh,
                         "LT", 0, cpElement, &_link_table,
                         cpEnd);

  if (!_link_table) 
    return errh->error("LinkTableMulti not specified");
  if (_link_table && _link_table->cast("SR2LinkTableMulti") == 0) {
    return errh->error("LinkTableMulti element is not a SR2LinkTableMulti");
  }

  return res;
}

void
SR2LinkMetricMulti::update_link(NodeAddress, NodeAddress, 
			   Vector<SR2RateSize>, 
			   Vector<int>, Vector<int>, 
			   uint32_t) {}

ELEMENT_REQUIRES(bitrate)
ELEMENT_PROVIDES(SR2LinkMetricMulti)

