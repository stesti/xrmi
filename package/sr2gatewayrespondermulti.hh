#ifndef CLICK_SR2GATEWAYRESPONDERMULTI_HH
#define CLICK_SR2GATEWAYRESPONDERMULTI_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/timer.hh>
#include <click/ipaddress.hh>
#include <click/etheraddress.hh>
#include <click/vector.hh>
#include <click/hashmap.hh>
CLICK_DECLS

/*
 * =c
 * SR2GatewayResponder(ETHTYPE, IP, ETH, PERIOD, LinkTable element, 
 * ARPTable element, GatewaySelector element)
 * =s Wifi, Wireless Routing
 * Responds to queries destined for this node.
 */

class SR2GatewayResponderMulti : public Element {
 public:
  
  SR2GatewayResponderMulti();
  ~SR2GatewayResponderMulti();
  
  const char *class_name() const		{ return "SR2GatewayResponderMulti"; }
  const char *port_count() const		{ return PORTS_0_1; }
  const char *processing() const		{ return PUSH; }
  const char *flow_code() const			{ return "#/#"; }

  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);
  void run_timer(Timer *);
  void add_handlers();

 private:

  IPAddress _ip;         // My IP address.
  uint32_t _et;          // This protocol's ethertype
  unsigned int _period;  // msecs
  bool _debug;

  class ARPTableMulti *_arp_table;
  class SR2GatewaySelectorMulti *_gw_sel;
  class SR2LinkTableMulti *_link_table;
  class AvailableInterfaces *_if_table;

  Timer _timer;

  static int write_handler(const String &, Element *, void *, ErrorHandler *);
  static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
