#ifndef CLICK_SR2FORWARDERMULTI_HH
#define CLICK_SR2FORWARDERMULTI_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/timer.hh>
#include <click/ipaddress.hh>
#include <click/etheraddress.hh>
#include <click/vector.hh>
#include <elements/wifi/path.hh>
#include "sr2nodemulti.hh"
#include "sr2packetmulti.hh"
#include "arptablemulti.hh"
CLICK_DECLS

/*
 * =c
 * SR2ForwarderMulti(ETHERTYPE, IP, ETH, ARPTable element)
 * =s Wifi, Wireless Routing
 * Forwards source-routed packets.
 * =d
 * DSR-inspired ad-hoc routing protocol.
 * Input 0: packets that I receive off the wire
 * Output 0: Outgoing ethernet packets that I forward
 * Output 1: packets that were addressed to me.
 *
 */

class SR2ForwarderMulti : public Element {
public:
  
  SR2ForwarderMulti();
  ~SR2ForwarderMulti();
  
  const char *class_name() const		{ return "SR2ForwarderMulti"; }
  const char *port_count() const		{ return "1/2"; }
  const char *processing() const		{ return PUSH; }

  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);

  /* handler stuff */
  void add_handlers();
  String print_stats();

  void push(int, Packet *);
  
  Packet *encap(Packet *, Vector<NodeAirport>, int flags);
  IPAddress ip() { return _ip; }
  //EtherAddress eth() { return _eth; }

private:

  IPAddress _ip;    // My IP address.
  //EtherAddress _eth; // My ethernet address.
  uint16_t _et;     // This protocol's ethertype

  /* statistics for handlers */
  int _datas;
  int _databytes;

  class AvailableInterfaces *_if_table;
  class SR2LinkTableMulti *_link_table;
  class ARPTableMulti *_arp_table;

  static String read_handler(Element *, void *);
};

CLICK_ENDDECLS
#endif
