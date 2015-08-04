#ifndef CLICK_SR2STRIPHEADERMULTI_HH
#define CLICK_SR2STRIPHEADERMULTI_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 * SR2StripHeader()
 * =s Wifi, Wireless Routing
 * Strips outermost SR header
 * =d
 * Removes the outermost SR header from SR packets based on the SR Header
 * annotation.
 * =a SR2CheckHeader
 */

class SR2StripHeaderMulti : public Element {

 public:
  
  SR2StripHeaderMulti();
  ~SR2StripHeaderMulti();
  
  const char *class_name() const	{ return "SR2StripHeaderMulti"; }
  const char *port_count() const	{ return PORTS_1_1; }

  Packet *simple_action(Packet *);
  
};

CLICK_ENDDECLS
#endif
