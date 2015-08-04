#ifndef CLICK_SR2GATEWAYSELECTORMULTI_HH
#define CLICK_SR2GATEWAYSELECTORMULTI_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/timer.hh>
#include <click/ipaddress.hh>
#include <click/etheraddress.hh>
#include <click/vector.hh>
#include <click/hashmap.hh>
#include <click/dequeue.hh>
#include <elements/wifi/path.hh>
CLICK_DECLS

/*
 * =c
 * SR2GatewaySelector(IP, ETH, ETHTYPE, LinkTable element, ARPTable element,  
 *                    [PERIOD timeout], [GW is_gateway])
 * =s Wifi, Wireless Routing
 * Select a gateway to send a packet to based on TCP connection
 * state and metric to gateway.
 * =d
 * This element provides proactive gateway selection.  
 * Each gateway broadcasts an ad every PERIOD msec.  
 * Non-gateway nodes select the gateway with the best 
 * metric and forward ads.
 */

class SR2GatewaySelectorMulti : public Element {
 public:
  
  SR2GatewaySelectorMulti();
  ~SR2GatewaySelectorMulti();
  
  const char *class_name() const		{ return "SR2GatewaySelectorMulti"; }
  const char *port_count() const		{ return PORTS_1_1; }
  const char *processing() const		{ return PUSH; }
  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);

  /* handler stuff */
  void add_handlers();
  String print_gateway_stats();

  void push(int, Packet *);
  void run_timer(Timer *);

  IPAddress best_gateway();
  bool is_gateway() { return _is_gw; }

  bool update_link(NodeAddress from, NodeAddress to, uint32_t seq, uint32_t metric);

  static void static_forward_ad_hook(Timer *, void *e) { 
    ((SR2GatewaySelectorMulti *) e)->forward_ad_hook(); 
  }

private:

  // List of query sequence #s that we've already seen.
  class Seen {
   public:
    Seen();
    Seen(IPAddress gw, u_long seq, int fwd, int rev) {
	_gw = gw; 
	_seq = seq; 
	_count = 0;
	(void) fwd, (void) rev;
    }
    IPAddress _gw;
    uint32_t _seq;
    int _count;
    Timestamp _when; /* when we saw the first query */
    Timestamp _to_send;
    bool _forwarded;
  };
  
  DEQueue<Seen> _seen;

  class GWInfo {
  public:
	GWInfo() {}
	GWInfo(const GWInfo &e) :
		_ip(e._ip),
		_first_update(e._first_update),
		_last_update(e._last_update),
		_seen(e._seen) {
	}
    IPAddress _ip;
    Timestamp _first_update;
    Timestamp _last_update;
    int _seen;
  };

  typedef HashMap<IPAddress, GWInfo> GWTable;
  typedef GWTable::const_iterator GWIter;

  GWTable _gateways;

  typedef HashMap<IPAddress, IPAddress> IPTable;
  typedef IPTable::const_iterator IPIter;

  IPTable _ignore;
  IPTable _allow;

  bool _is_gw;
  uint32_t _seq;      // Next query sequence number to use.
  IPAddress _ip;    // My IP address.
  uint16_t _et;     // This protocol's ethertype
  unsigned int _period; // msecs
  unsigned int _jitter; // msecs
  unsigned int _expire; // msecs

  class SR2LinkTableMulti *_link_table;
  class AvailableInterfaces *_if_table;
  class ARPTableMulti *_arp_table;

  Timer _timer;

  void start_ad();
  void send(WritablePacket *, EtherAddress);
  void forward_ad(Seen *s);
  void forward_ad_hook();
  void cleanup();

  static int write_handler(const String &, Element *, void *, ErrorHandler *);
  static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
