#ifndef CLICK_SR2SETCHECKSUMMULTI_HH
#define CLICK_SR2SETCHECKSUMMULTI_HH

/*
 * =c
 * SR2SetChecksumMulti()
 * =s Wifi, Wireless Routing
 * Set Checksum for Source Routed packet.
 * =d
 * Expects a SR MAC packet as input. Calculates the SR header's checksum 
 * and sets the version and checksum header fields.
 * =a SR2CheckHeader 
 */

#include <click/element.hh>
#include <click/glue.hh>
CLICK_DECLS

class SR2SetChecksumMulti : public Element {
public:
  SR2SetChecksumMulti();
  ~SR2SetChecksumMulti();
  
  const char *class_name() const		{ return "SR2SetChecksumMulti"; }
  const char *port_count() const		{ return PORTS_1_1; }
  const char *processing() const		{ return AGNOSTIC; }

  Packet *simple_action(Packet *);
};

CLICK_ENDDECLS
#endif
