/*
 * sr2setchecksummulti.{cc,hh} -- element sets SR header checksum
 * John Bicket
 * apapted from setwifichecksum.{cc,hh} by Douglas S. J. De Couto
 * adapted from setipchecksum.{cc,hh} by Robert Morris
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
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
#include "sr2setchecksummulti.hh"
#include <click/glue.hh>
#include "sr2packetmulti.hh"
#include <clicknet/ether.h>
#include <clicknet/ip.h>
CLICK_DECLS

SR2SetChecksumMulti::SR2SetChecksumMulti()
{
}

SR2SetChecksumMulti::~SR2SetChecksumMulti()
{
}

Packet *
SR2SetChecksumMulti::simple_action(Packet *p_in)
{
  WritablePacket *p = p_in->uniqueify();
  if (!p) {
    return 0;
  }
  click_ether *eh = (click_ether *) p->data();
  struct sr2packetmulti *pk = (struct sr2packetmulti *) (eh+1);
  unsigned plen = p->length();
  unsigned int tlen = 0;
  if (!pk)
    goto bad;
  if ((pk->_type & SR2_PT_DATA) || (pk->_type & SR2_PT_CHSCINFO) || (pk->_type & SR2_PT_CHASSIGN) || (pk->_type & SR2_PT_CHNGWARN)) {
    tlen = pk->hlen_with_data();
  } else {
    tlen = pk->hlen_wo_data();
  }
  if (plen < sizeof(struct sr2packetmulti))
    goto bad;
  if (tlen > plen - sizeof(click_ether))
    goto bad;
  pk->_version = _sr2_version;
  pk->set_checksum();
  return p;
 bad:
  click_chatter("%{element} :: %s :: bad lengths plen %d, tlen %d", 
		this, 
		__func__, 
		plen,
		tlen);
  p->kill();
  return(0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SR2SetChecksumMulti)

