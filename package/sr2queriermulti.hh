#ifndef CLICK_SR2QUERIERMULTI_HH
#define CLICK_SR2QUERIERMULTI_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/timer.hh>
#include <click/etheraddress.hh>
#include <click/hashmap.hh>
#include <elements/wifi/path.hh>
#include "sr2packetmulti.hh"
#include "sr2nodemulti.hh"
CLICK_DECLS

/*
 * =c
 * SR2QuerierMulti(ETH, SR2Forwarder element, LinkTable element)
 * =s Wifi, Wireless Routing
 * Sends route queries if it can't find a valid source route.
 */

class SR2QuerierMulti : public Element {
public:
  
  SR2QuerierMulti();
  ~SR2QuerierMulti();
  
  const char *class_name() const		{ return "SR2QuerierMulti"; }
  const char *port_count() const		{ return "1/2"; }
  const char *processing() const		{ return PUSH; }
  const char *flow_code() const			{ return "#/#"; }
  int configure(Vector<String> &conf, ErrorHandler *errh);

  /* handler stuff */
  void add_handlers();
  String print_queries();

  void push(int, Packet *);
  void send_query(IPAddress);

private:

  class DstInfoMulti {
  public:
    DstInfoMulti() {memset(this, 0, sizeof(*this)); }
    DstInfoMulti(IPAddress ip) {memset(this, 0, sizeof(*this)); _ip = ip;}
    IPAddress _ip;
    int _best_metric;
    int _count;
    Timestamp _last_query;
    SR2PathMulti _p;
    Timestamp _last_switch;    // last time we picked a new best route
    Timestamp _first_selected; // when _p was first selected as best route
  };
  
  typedef HashMap<IPAddress, DstInfoMulti> DstTableMulti;
  DstTableMulti _queries;

  uint32_t _seq;     // Next query sequence number to use.
  Timestamp _query_wait;
  Timestamp _time_before_switch_sec;

  IPAddress _ip;     // My IP address.
  uint16_t _et;      // This protocol's ethertype

  class SR2ForwarderMulti *_forwarder;
  class SR2LinkTableMulti *_link_table;
  class AvailableInterfaces *_if_table;

  bool _debug;

  static int write_handler(const String &, Element *, void *, ErrorHandler *);
  static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
