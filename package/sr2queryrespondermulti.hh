#ifndef CLICK_SR2QUERYRESPONDERMULTI_HH
#define CLICK_SR2QUERYRESPONDERMULTI_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/timer.hh>
#include <click/ipaddress.hh>
#include <click/etheraddress.hh>
#include <click/vector.hh>
#include <click/hashmap.hh>
#include <click/dequeue.hh>
#include "availableinterfaces.hh"
#include "sr2pathmulti.hh"
#include "sr2nodemulti.hh"
CLICK_DECLS

/*
 * =c
 * SR2QueryResponder(ETHERTYPE, IP, ETH, LinkTable element, ARPTable element)
 * =s Wifi, Wireless Routing
 * Responds to queries destined for this node.
 */

class SR2QueryResponderMulti : public Element {
 public:
  
  SR2QueryResponderMulti();
  ~SR2QueryResponderMulti();
  
  const char *class_name() const		{ return "SR2QueryResponderMulti"; }
  const char *port_count() const		{ return PORTS_1_1; }
  const char *processing() const		{ return PUSH; }
  const char *flow_code() const			{ return "#/#"; }
  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);

  /* handler stuff */
  void add_handlers();

  void push(int, Packet *);

 private:

  IPAddress _ip;    // My IP address.
  uint16_t _et;     // This protocol's ethertype

  class Seen {
  public:
    Seen();
    Seen(IPAddress src, IPAddress dst, uint32_t seq) {
      _src = src;
      _dst = dst;
      _seq = seq;
    }
    IPAddress _src;
    IPAddress _dst;
    uint32_t _seq;
    SR2PathMulti last_path_response;
  };

  DEQueue<Seen> _seen;

  class SR2LinkTableMulti *_link_table;
  class ARPTableMulti *_arp_table;
  class AvailableInterfaces *_if_table;

  bool _debug;

  bool update_link(NodeAddress from, NodeAddress to, uint32_t seq, uint32_t metric);
  void start_reply(IPAddress src, IPAddress qdst, uint32_t seq);
  void forward_reply(struct sr2packetmulti *pk);
  void send(WritablePacket *);

  static int write_handler(const String &, Element *, void *, ErrorHandler *);
  static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
