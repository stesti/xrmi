#ifndef CLICK_SR2METRICFLOODMULTI_HH
#define CLICK_SR2METRICFLOODMULTI_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/timer.hh>
#include <click/ipaddress.hh>
#include <click/etheraddress.hh>
#include <click/vector.hh>
#include <click/hashmap.hh>
#include <click/dequeue.hh>
#include "sr2nodemulti.hh"
#include "arptablemulti.hh"
CLICK_DECLS

/*
 * =c
 * SR2MetricFloodMulti(ETHERTYPE, IP, ETH, LinkTable element, ARPTable element)
 * =s Wifi, Wireless Routing
 * =d
 * Floods a packet with previous hops based on Link Metrics.
 */

class SR2MetricFloodMulti : public Element {
 public:
  
  SR2MetricFloodMulti();
  ~SR2MetricFloodMulti();
  
  const char *class_name() const		{ return "SR2MetricFloodMulti"; }
  const char *port_count() const		{ return "1/2"; }
  const char *processing() const		{ return PUSH; }
  const char *flow_code() const			{ return "#/#"; }
  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);

  /* handler stuff */
  void add_handlers();

  void push(int, Packet *);

  bool update_link(NodeAddress from, NodeAddress to, 
		   uint32_t seq, uint32_t age,		   
		   uint32_t metric);

  static void static_forward_query_hook(Timer *, void *e) { 
    ((SR2MetricFloodMulti *) e)->forward_query_hook(); 
  }

 private:

  // List of query sequence #s that we've already seen.
  class Seen {
  public:
    Seen();
    Seen(IPAddress src, IPAddress dst, uint32_t seq, int fwd, int rev) {
      _src = src; 
      _dst = dst; 
      _seq = seq; 
      _count = 0;
      (void) fwd, (void) rev;
    }
    IPAddress _src;
    IPAddress _dst;
    uint32_t _seq;
    int _count;
    Timestamp _when; 
    Timestamp _to_send;
    bool _forwarded;
  };

  DEQueue<Seen> _seen;

  IPAddress _ip;     // My IP address.
  uint16_t _et;      // This protocol's ethertype

  class SR2LinkTableMulti *_link_table;
  class ARPTableMulti *_arp_table;
  class AvailableInterfaces *_if_table;

  unsigned int _jitter; // msecs
  bool _debug;

  void forward_query(Seen *s, EtherAddress _eth);
  void forward_query_hook();

  static int write_handler(const String &, Element *, void *, ErrorHandler *);
  static String read_handler(Element *, void *);

};


CLICK_ENDDECLS
#endif
