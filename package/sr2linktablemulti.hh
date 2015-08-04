#ifndef CLICK_SR2LINKTABLEMULTI_HH
#define CLICK_SR2LINKTABLEMULTI_HH
#include <click/ipaddress.hh>
#include <click/glue.hh>
#include <click/timer.hh>
#include <click/element.hh>
#include <click/bighashmap.hh>
#include <click/hashmap.hh>
#include "sr2pathmulti.hh"
#include "sr2nodemulti.hh"
CLICK_DECLS

/*
 * =c
 * SR2LinkTableMulti(IP Address, [STALE timeout])
 * =s Wifi
 * Keeps a Multiradio Link state database and calculates Weighted Shortest Path
 * for other elements
 * =d
 * Runs dijkstra's algorithm occasionally.
 * =a ARPTable
 *
 */
class NodePair {
  public:

    NodeAddress _to;
    NodeAddress _from;

    NodePair()
	: _to(), _from() {
    }

    NodePair(NodeAddress from, NodeAddress to)
	: _to(to), _from(from) {
    }

    bool contains(NodeAddress foo) const {
	return (foo == _to || foo == _from);
    }

    inline hashcode_t hashcode() const {
	return CLICK_NAME(hashcode)(_to) + CLICK_NAME(hashcode)(_from);
    }

    inline bool operator==(NodePair other) const {
	return (other._to == _to && other._from == _from);
    }

};


class SR2LinkTableMulti: public Element{
public:

  /* generic click-mandated stuff*/
  SR2LinkTableMulti();
  ~SR2LinkTableMulti();
  void add_handlers();
  const char* class_name() const { return "SR2LinkTableMulti"; }
  int initialize(ErrorHandler *);
  void run_timer(Timer *);
  int configure(Vector<String> &conf, ErrorHandler *errh);
  void take_state(Element *, ErrorHandler *);
  void *cast(const char *n);
  /* read/write handlers */
  String print_routes(bool, bool);
  String print_links();
  String print_hosts();

  static int static_update_link(const String &arg, Element *e,
				void *, ErrorHandler *errh);
  void clear();

  /* other public functions */
  String route_to_string(SR2PathMulti p);
  bool update_link(NodeAddress from, NodeAddress to,
			uint32_t seq, uint32_t age, uint32_t metric);
  bool update_both_links(NodeAddress a, NodeAddress b,
			uint32_t seq, uint32_t age, uint32_t metric) {
    if (update_link(a,b,seq,age, metric)) {
      return update_link(b,a,seq,age, metric);
    }
    return false;
  }

  uint32_t get_link_metric(NodeAddress from, NodeAddress to);
  uint32_t get_link_seq(NodeAddress from, NodeAddress to);
  uint32_t get_link_age(NodeAddress from, NodeAddress to);
	uint16_t get_if_def(IPAddress node);
  uint32_t get_link_rate(NodeAddress from, NodeAddress to);
  void set_link_rate(NodeAddress, NodeAddress, uint32_t);
  uint32_t get_link_retries(NodeAddress from, NodeAddress to);
  void set_link_retries(NodeAddress, NodeAddress, uint32_t);
  uint32_t get_link_probe(NodeAddress from, NodeAddress to);
  void set_link_probe(NodeAddress, NodeAddress, uint32_t);
	void change_if(NodeAddress, uint16_t);

  bool valid_route(const Vector<NodeAirport> &route);
  unsigned get_route_metric(const Vector<NodeAirport> &route);
  Vector<IPAddress> get_neighbors(IPAddress ip);
	HashMap<NodeAddress,int> get_neighbors_if(int iface);
  void dijkstra(bool);
  void clear_stale();
  Vector<NodeAirport> best_route(IPAddress dst, bool from_me);
	//Vector<NodeAirport> rewrite_def(Vector<NodeAirport>);

  Vector< Vector<NodeAirport> > top_n_routes(IPAddress dst, int n);
  uint32_t get_host_metric_to_me(IPAddress s);
  uint32_t get_host_metric_from_me(IPAddress s);
  Vector<IPAddress> get_hosts();

  class SR2LinkMulti {
  public:
    NodeAddress _from;
    NodeAddress _to;
    uint32_t _seq;
    uint32_t _metric;
    SR2LinkMulti() : _from(), _to(), _seq(0), _metric(0) { }
    SR2LinkMulti(NodeAddress from, NodeAddress to, uint32_t seq, uint32_t metric) {
      _from = from;
      _to = to;
      _seq = seq;
      _metric = metric;
    }
  };

  SR2LinkMulti random_link();


  typedef HashMap<IPAddress, IPAddress> IPTable;
  typedef IPTable::const_iterator IPIter;

  IPTable _blacklist;

  Timestamp dijkstra_time;
protected:
  class SR2LinkInfoMulti {
  public:
    NodeAddress _from;
    NodeAddress _to;
    unsigned _metric;
    uint32_t _seq;
    uint32_t _age;
    uint32_t _rate;
    uint32_t _probe;
    uint32_t _retries;
    Timestamp _last_updated;
    SR2LinkInfoMulti() {
      _from = NodeAddress();
      _to = NodeAddress();
      _metric = 0;
      _seq = 0;
      _age = 0;
      _rate = 0;
      _probe = 0;
      _retries = 0;
    }

    SR2LinkInfoMulti(NodeAddress from, NodeAddress to,
	     uint32_t seq, uint32_t age, unsigned metric) {
      _from = from;
      _to = to;
      _metric = metric;
      _seq = seq;
      _age = age;
      _rate = 0;
      _probe = 0;
       _retries = 0;
      _last_updated.set_now();
    }

    SR2LinkInfoMulti(const SR2LinkInfoMulti &p) :
      _from(p._from), _to(p._to),
      _metric(p._metric), _seq(p._seq),
      _age(p._age), _rate(p._rate), 
      _probe(p._probe), _retries(p._retries),
      _last_updated(p._last_updated)
    { }

    uint32_t age() {
	Timestamp now = Timestamp::now();
	return _age + (now.sec() - _last_updated.sec());
    }
    void update(uint32_t seq, uint32_t age, unsigned metric) {
      if (seq <= _seq) {
	return;
      }
      _metric = metric;
      _seq = seq;
      _age = age;
      _last_updated.set_now();
    }

  };

	typedef HashMap<uint16_t, uint32_t> MetricTable;
	typedef HashMap<uint16_t, uint32_t>::const_iterator MetricIter;

  class SR2HostInfoMulti {
  public:
    IPAddress _ip;
    uint16_t _if_from_me;
    uint16_t _if_to_me;
		uint16_t _if_def;
    uint32_t _metric_from_me;
    uint32_t _metric_to_me;

    NodeAddress _prev_from_me;
    NodeAddress _prev_to_me;

		MetricTable _metric_table_from_me;
	  MetricTable _metric_table_to_me;

    bool _marked_from_me;
    bool _marked_to_me;

	Vector<int> _interfaces;

    SR2HostInfoMulti(IPAddress p) {
	  _ip = p;
	  _if_from_me = 0;
	  _if_to_me = 0;
		_if_def = 0;
      _metric_from_me = 0;
      _metric_to_me = 0;
      _prev_from_me = NodeAddress();
      _prev_to_me = NodeAddress();
      _marked_from_me = false;
      _marked_to_me = false;
    }
    SR2HostInfoMulti() {
      _ip = IPAddress();
	  _if_from_me = 0;
	  _if_to_me = 0;
		_if_def = 0;
      _metric_from_me = 0;
      _metric_to_me = 0;
      _prev_from_me = NodeAddress();
      _prev_to_me = NodeAddress();
      _marked_from_me = false;
      _marked_to_me = false;
    }

    SR2HostInfoMulti(const SR2HostInfoMulti &p) :
      _ip(p._ip),
	  _if_from_me(p._if_from_me),
	  _if_to_me(p._if_to_me),
		_if_def(p._if_def),
      _metric_from_me(p._metric_from_me),
      _metric_to_me(p._metric_to_me),
      _prev_from_me(p._prev_from_me),
      _prev_to_me(p._prev_to_me),
      _marked_from_me(p._marked_from_me),
      _marked_to_me(p._marked_to_me)
    { }

    void clear(bool from_me) {
      if (from_me ) {
		_prev_from_me = NodeAddress();
		_if_from_me = 0;
		_metric_from_me = 0;
		_metric_table_from_me.clear();
		_marked_from_me = false;
      } else {
		_prev_to_me = NodeAddress();
		_if_to_me = 0;
		_metric_to_me = 0;
		_metric_table_to_me.clear();
		_marked_to_me = false;
      }
    }

	void new_interface(uint16_t iface){
		if (iface == 0) {
			return;
		}
		for (int i=0; i<_interfaces.size(); i++){
			if (iface == _interfaces[i]){
				return;
			}
		}
		if ((iface >= 256) && (iface <= 511)){
			_if_def = iface;
		}
		_interfaces.push_back(iface);
	}
	
	void update_interface(uint16_t old_iface, uint16_t new_iface){
		for (Vector<int>::iterator iter = _interfaces.begin(); iter != _interfaces.end(); iter ++){
			if (old_iface == *iter){
				_interfaces.erase(iter);
				_interfaces.push_back(new_iface);
			}
		}
	}
	

  };

  typedef HashMap<IPAddress, SR2HostInfoMulti> SR2HTableMulti;
  typedef SR2HTableMulti::const_iterator SR2HTIterMulti;


  typedef HashMap<NodePair, SR2LinkInfoMulti> SR2LTableMulti;
  typedef SR2LTableMulti::const_iterator SR2LTIterMulti;

  SR2HTableMulti _hosts;
  SR2LTableMulti _links;


  IPAddress _ip;
  Timestamp _stale_timeout;
  Timer _timer;
};



CLICK_ENDDECLS
#endif /* CLICK_LINKTABLE_HH */
