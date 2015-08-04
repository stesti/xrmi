/*
 * sr2checkheadermulti.{cc,hh} -- element checks SR header for correctness
 * (checksums, lengths)
 * John Bicket
 * apapted from checkwifiheader.{cc,hh} by Douglas S. J. De Couto
 * from checkipheader.{cc,hh} by Robert Morris
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
#include <click/etheraddress.hh>
#include <click/glue.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include "sr2packetmulti.hh"
#include "sr2checkheadermulti.hh"
CLICK_DECLS

SR2CheckHeaderMulti::SR2CheckHeaderMulti()
 : _drops(0), _checksum(false)
{
}

SR2CheckHeaderMulti::~SR2CheckHeaderMulti()
{
}

int
SR2CheckHeaderMulti::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (cp_va_kparse_remove_keywords(conf, this, errh,
					"CHECKSUM", 0, cpBool, &_checksum,
					cpEnd) < 0) {
    return -1;
  }
 return 0;
}

Packet *
SR2CheckHeaderMulti::simple_action(Packet *p)
{
  click_ether *eh = (click_ether *) p->data();
  struct sr2packetmulti *pk = (struct sr2packetmulti *) (eh+1);
  const click_ip *ip = reinterpret_cast<const click_ip *>(pk->data());
  unsigned int tlen = 0;
  if (!pk || !ip)
    goto bad;
  if (p->length() < sizeof(click_ether) + sizeof(struct sr2packetmulti)) {
    click_chatter("%{element} :: %s :: packet truncated", this, __func__);
    goto bad;
  }
  if (_checksum && !pk->check_checksum()) {
    click_chatter("%{element} :: %s :: failed checksum", this, __func__);
    p->kill();
    return 0;
  }
  if ((pk->_type & SR2_PT_DATA) || (pk->_type & SR2_PT_CHSCINFO) || (pk->_type & SR2_PT_CHASSIGN) || (pk->_type & SR2_PT_CHNGWARN)) {
    tlen = pk->hlen_with_data();
  } else {
    tlen = pk->hlen_wo_data();
  }
  if (pk->_version != _sr2_version) {
    _bad_table.insert(EtherAddress(eh->ether_shost), pk->_version);
    click_chatter ("%{element} :: %s :: unknown sr version %x from %s", 
		   this,
		   __func__,
		   pk->_version,
		   EtherAddress(eh->ether_shost).unparse().c_str());
     
    goto bad;
  }
  if (tlen > p->length()) { 
    /* can only check inequality, as short packets are padded to a
       minimum frame size for wavelan and ethernet */
    click_chatter("%{element} :: %s :: bad packet size, wanted %d, only got %d", 
		  this,
		  __func__,
		  tlen + sizeof(click_ether), 
		  p->length());
    goto bad;
  }
  if (pk->next() > pk->num_links()){
    click_chatter("%{element} :: %s :: data with bad next hop from %s\n", 
		  this,
		  __func__,
		  pk->get_link_node(0).unparse().c_str());
    goto bad;
  }
  /* set the ip header anno */
  p->set_ip_header(ip, sizeof(click_ip));
  return(p);
 bad:
  if (_drops == 0) {
    click_chatter("%{element} :: %s :: first drop", this, __func__);
  }
  _drops++;
  if (noutputs() == 2) {
    output(1).push(p);
  } else {
    p->kill();
  }
  return 0;
}

String 
SR2CheckHeaderMulti::bad_nodes() {

  StringAccum sa;
  for (BadTable::const_iterator i = _bad_table.begin(); i.live(); i++) {
    uint8_t version = i.value();
    EtherAddress dst = i.key();
    sa << this << " eth " << dst.unparse() << " version " << (int) version << "\n";
  }

  return sa.take_string();
}

enum { H_DROPS, H_BAD_VERSION };

String
SR2CheckHeaderMulti::read_handler(Element *e, void *thunk)
{
  SR2CheckHeaderMulti *td = (SR2CheckHeaderMulti *)e;
    switch ((uintptr_t) thunk) {
    case H_DROPS:   
      return String(td->drops()) + "\n";
    case H_BAD_VERSION: 
      return td->bad_nodes();
    default:
      return String() + "\n";
    }
}

void
SR2CheckHeaderMulti::add_handlers()
{
  add_read_handler("drops", read_handler, H_DROPS);
  add_read_handler("bad_version", read_handler, H_BAD_VERSION);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SR2CheckHeaderMulti)

