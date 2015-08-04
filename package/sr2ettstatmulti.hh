#ifndef CLICK_SR2ETTSTATMULTI_HH
#define CLICK_SR2ETTSTATMULTI_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <click/etheraddress.hh>
#include <click/dequeue.hh>
#include <click/hashmap.hh>
#include <clicknet/wifi.h>
#include "sr2nodemulti.hh"
#include "sr2linktablemulti.hh"
CLICK_DECLS

class SR2RateSize {
  public:
    SR2RateSize(int rate, int size): _rate(rate), _size(size) { };
    int _rate;
    int _size;
    inline bool operator==(SR2RateSize other) { return (other._rate == _rate && other._size == _size); }
};

class Probe {
  public:
    Probe(const Timestamp &when, 
          uint32_t seq,
          int rate,
          int size,
          uint32_t rssi,
          uint32_t noise) : _when(when), _seq(seq), _rate(rate), _size(size), _rssi(rssi), _noise(noise) { }

    Timestamp _when;  
    uint32_t _seq;
    int _rate;
    int _size;
    uint32_t _rssi;
    uint32_t _noise;
};

class ProbeListMulti {
  public:
    ProbeListMulti() : _period(0), _tau(0) { }
    ProbeListMulti(const EtherAddress &eth, const NodeAddress &node,
              uint32_t period, 
              uint32_t tau) : _eth(eth), _node(node), _period(period), _tau(tau), _sent(0) { }

    EtherAddress _eth;
		NodeAddress _node;
    uint32_t _period;               // period of this node's probes, as reported by the node
    uint32_t _tau;                  // this node's stats averaging period, as reported by the node
    uint32_t _sent;
    uint32_t _num_probes;
    uint32_t _seq;
    Vector<SR2RateSize> _probe_types;
    Vector<int> _fwd_rates;
    Timestamp _last_rx;
    DEQueue<Probe> _probes;         // most recently received probes

    int fwd_rate(int rate, int size) {
      if (Timestamp::now() - _last_rx > Timestamp::make_msec(_tau)) {
        return 0;
      }
      for (int x = 0; x < _probe_types.size(); x++) {
        if (_probe_types[x]._size == size && _probe_types[x]._rate == rate) {
          return _fwd_rates[x];
        }
      }
      return 0;
    }

    int rev_rate(const Timestamp &start, int rate, int size) {
      Timestamp now = Timestamp::now();
      Timestamp earliest = now - Timestamp::make_msec(_tau);
      if (_period == 0) {
	click_chatter("period is 0\n");
	return 0;
      }
      int num = 0;
      for (int i = _probes.size() - 1; i >= 0; i--) {
	if (earliest > _probes[i]._when) {
	  break;
	} 
	if ( _probes[i]._size == size &&
	    _probes[i]._rate == rate) {
	  num++;
	}
      }
      Timestamp since_start = now - start;
      uint32_t ms_since_start = WIFI_MAX(0, since_start.msecval());
      uint32_t fake_tau = WIFI_MAX(_tau, ms_since_start);
      assert(_probe_types.size());
      uint32_t num_expected = fake_tau / _period;
      if (_sent / _num_probes < num_expected) {
	num_expected = _sent / _num_probes;
      }
      if (!num_expected) {
	num_expected = 1;
      }
      return WIFI_MAX(100, 100 * num / num_expected);
    }

    int rev_rssi(int rate, int size) {
      Timestamp now = Timestamp::now();
      Timestamp earliest = now - Timestamp::make_msec(_tau);
      if (_period == 0) {
	click_chatter("period is 0\n");
	return 0;
      }
      int num = 0;
      int sum = 0;
      for (int i = _probes.size() - 1; i >= 0; i--) {
	if (earliest > _probes[i]._when) {
	  break;
	} 
	if ( _probes[i]._size == size &&
	    _probes[i]._rate == rate) {
	  num++;
	  sum += _probes[i]._rssi;
	}
      }
      if (!num) {
	      return -1;
      }
      return  (sum / num);
    }

    int rev_noise(int rate, int size) {
      Timestamp now = Timestamp::now();
      Timestamp earliest = now - Timestamp::make_msec(_tau);
      if (_period == 0) {
	click_chatter("period is 0\n");
	return 0;
      }
      int num = 0;
      int sum = 0;
      for (int i = _probes.size() - 1; i >= 0; i--) {
	if (earliest > _probes[i]._when) {
	  break;
	} 
	if ( _probes[i]._size == size &&
	    _probes[i]._rate == rate) {
	  num++;
	  sum += _probes[i]._noise;
	}
      }
      if (!num) {
	      return -1;
      }
      return  (sum / num);
    }
};

class SR2ETTStatMulti : public Element { 
  public:
	
	SR2ETTStatMulti();
	~SR2ETTStatMulti();	
	
	const char *class_name() const		{ return "SR2ETTStatMulti"; }
	const char *port_count() const		{ return "1/0-1"; }
	const char *processing() const		{ return PUSH; }

	int configure(Vector<String> &, ErrorHandler *);
	int initialize(ErrorHandler *);

	Packet *simple_action(Packet *);

	/* handler stuff */
	void add_handlers();
	String print_bcast_stats();

  private:

	Vector <SR2RateSize> _ads_rs;
	int _ads_rs_index;
	
	Vector <EtherAddress> _neighbors;
	int _neighbors_index;

	typedef HashMap<EtherAddress, ProbeListMulti> ProbeMap;
	typedef ProbeMap::const_iterator ProbeIter;

	ProbeMap _bcast_stats;

	Timestamp _start;

	uint16_t _et; 
	IPAddress _ip;
	uint16_t _iface;
	EtherAddress _eth;
	uint32_t _tau; // msecs
	uint32_t _period; // msecs
	uint32_t _expire; // msecs

	uint32_t _seq;
	uint32_t _sent;

	class SR2LinkMetricMulti *_link_metric;
	class ARPTableMulti *_arp_table;
	class AvailableInterfaces *_if_table;

	Timer _timer;

	void run_timer(Timer *);
	void reset();
	void send_probe();

	static int write_handler(const String &, Element *, void *, ErrorHandler *);
	static String read_handler(Element *, void *);

  public:

	const ProbeMap *bcast_stats() { return &_bcast_stats; }
	const Vector<SR2RateSize> *ads_rs() { return &_ads_rs; }
	Timestamp start() { return _start; }

};

CLICK_ENDDECLS
#endif

