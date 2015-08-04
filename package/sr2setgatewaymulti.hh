#ifndef CLICK_SR2SETGATEWAYMULTI_HH
#define CLICK_SR2SETGATEWAYMULTI_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/timer.hh>
#include <click/ipaddress.hh>
#include <click/etheraddress.hh>
#include <click/vector.hh>
#include <click/hashmap.hh>
#include <elements/wifi/linktable.hh>
#include <elements/ethernet/arptable.hh>
#include <elements/wifi/path.hh>
#include <click/ipflowid.hh>
#include <clicknet/tcp.h>
#include "sr2packetmulti.hh"
#include "sr2gatewayselectormulti.hh"
CLICK_DECLS

/*
 * =c
 * SR2SetGateway([GW ipaddress], [SEL GatewaySelector element])
 * =d
 * This element marks the gateway for a packet to be sent to.
 * Either manually specifiy an gw using the GW keyword
 * or automatically select it using a GatewaySelector element.
 */

class SR2SetGatewayMulti : public Element {
 public:
  
  SR2SetGatewayMulti();
  ~SR2SetGatewayMulti();
  
  const char *class_name() const		{ return "SR2SetGatewayMulti"; }
  const char *port_count() const		{ return "2/2"; }
  const char *processing() const		{ return PUSH; }
  const char *flow_code() const			{ return "#/#"; }
  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);

  /* handler stuff */
  void add_handlers();
  String print_flows();

  void push(int, Packet *);
  void run_timer(Timer *);

private:

  class FlowTableEntry {
  public:
    class IPFlowID _id;
    IPAddress _gw;
    Timestamp _oldest_unanswered;
    Timestamp _last_reply;
    int _outstanding_syns;
    bool _fwd_alive;
    bool _rev_alive;
    bool _all_answered;
    FlowTableEntry() {
      _all_answered = true;
      _fwd_alive = true;
      _rev_alive = true;
    }
    FlowTableEntry(const FlowTableEntry &e) : 
      _id(e._id),
      _gw(e._gw),
      _oldest_unanswered(e._oldest_unanswered),
      _last_reply(e._last_reply),
      _outstanding_syns(e._outstanding_syns),
      _fwd_alive(e._fwd_alive),
      _rev_alive(e._rev_alive),
      _all_answered(e._all_answered) { 
    }
    void saw_forward_packet() {
      if (_all_answered) {
	  _oldest_unanswered = Timestamp::now();
	  _all_answered = false;
      }
    }
    void saw_reply_packet() {
      _last_reply = Timestamp::now();
      _all_answered = true;
      _outstanding_syns = 0;
    }
    bool is_pending() const { return (_outstanding_syns > 0);}
    Timestamp age() { return Timestamp::now() - _last_reply; }
  };

  typedef HashMap<IPFlowID, FlowTableEntry> FlowTable;
  typedef FlowTable::const_iterator FTIter;
  FlowTable _flow_table;

  class SR2GatewaySelectorMulti *_gw_sel;
  IPAddress _gw;

  Timer _timer;
  uint32_t _period;

  void push_fwd(Packet *, IPAddress);
  void push_rev(Packet *);
  void cleanup();

  static int write_handler(const String &, Element *, void *, ErrorHandler *);
  static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
