#ifndef CLICK_AVAILABLEINTERFACES_HH
#define CLICK_AVAILABLEINTERFACES_HH
#include <click/element.hh>
#include <click/ipaddress.hh>
#include <click/etheraddress.hh>
#include <click/bighashmap.hh>
#include <click/glue.hh>
#include <click/timer.hh>
CLICK_DECLS

/*
=c

AvailableInterfaces()

=s Wifi, Wireless Station, Wireless AccessPoint

Tracks bit-rate capabilities of other stations.

=d

Tracks a list of bitrates other stations are capable of.

=h insert write-only
Inserts an ethernet address and a list of bitrates to the database.

=h remove write-only
Removes an ethernet address from the database.

=h rates read-only
Shows the entries in the database.

=a BeaconScanner
 */

class EtherPair {
public:
  EtherAddress _eth_from;
	EtherAddress _eth_to;
    EtherPair() {
    memset(this, 0, sizeof(*this));
  }

  EtherPair(EtherAddress eth_from) {
    memset(this, 0, sizeof(*this));
    _eth_from = eth_from;
	_eth_to = eth_from;
  }

  EtherPair(EtherAddress eth_from, EtherAddress eth_to) {
    memset(this, 0, sizeof(*this));
    _eth_from = eth_from;
	_eth_to = eth_to;
  }

  inline hashcode_t hashcode() const {
	return CLICK_NAME(hashcode)(_eth_to) + CLICK_NAME(hashcode)(_eth_from);
  }

  inline bool operator==(EtherPair other) const {
	return (other._eth_to == _eth_to && other._eth_from == _eth_from);
  }

};

class ChangingChannel {
  public:
    uint32_t _host;
    uint16_t _iface_old;
    uint16_t _iface_new;
    Timestamp _last_update;
    ChangingChannel() : _host(), _iface_old(0), _iface_new(0), _last_update(Timestamp::now()) { }
    ChangingChannel(uint32_t host, uint16_t iface_old, uint16_t iface_new) {
      _host = host;
      _iface_old = iface_old;
      _iface_new = iface_new;
      _last_update = Timestamp::now();
    }
  };

class AvailableInterfaces : public Element { public:

  AvailableInterfaces();
  ~AvailableInterfaces();

  const char *class_name() const		{ return "AvailableInterfaces"; }
  const char *port_count() const		{ return PORTS_0_0; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize (ErrorHandler *);
  void *cast(const char *n);
  bool can_live_reconfigure() const		{ return true; }

  void add_handlers();
  void take_state(Element *e, ErrorHandler *);
  
  void run_timer(Timer*);

  Vector<int> lookup(EtherPair);
  EtherAddress lookup_if(int);
  EtherAddress lookup_def();
	int lookup_def_id();
  int lookup_id(EtherAddress);

  bool check_if_local(EtherAddress);
  bool check_if_present(int);
  bool check_if_available(int);
  bool check_remote_available(EtherAddress);
  int check_channel_change(int);
  String get_if_name(int);
  void set_available(int);
  void set_unavailable(int);
  void set_remote_unavailable(EtherAddress,bool,ChangingChannel);
  void set_channel_change(int, int);
  
  void clean_wtable();

  void change_if(int,int);
  Vector<int> get_local_rates(int);

  int insert(EtherPair, Vector<int>);

  EtherAddress _bcast;
  bool _debug;
  
  Timer _timer;

  int parse_and_insert(String s, ErrorHandler *errh);

  class DstInfo {
  public:
    EtherAddress _eth;
    Vector<int> _rates;
    DstInfo() {
      memset(this, 0, sizeof(*this));
    }

    DstInfo(EtherAddress eth) {
      memset(this, 0, sizeof(*this));
      _eth = eth;
    }
  };


  class LocalIfInfo {
  public:
	int _iface;
    bool _available;
    int _switch_to;
    EtherAddress _eth;
    Vector<int> _rates;
    String _iface_name;

    LocalIfInfo() {
      //memset(this, 0, sizeof(*this));
      _available = true;
      _switch_to=0;
    }

    LocalIfInfo(EtherAddress eth, String iface_name) {
      //memset(this, 0, sizeof(*this));
      _eth = eth;
      _available = true;
			_iface_name = String(iface_name);
			_switch_to=0;
    }
    
    LocalIfInfo(EtherAddress eth, bool available) {
      //memset(this, 0, sizeof(*this));
      _eth = eth;
      _available = available;
      _switch_to=0;
    }
    
    void set_available(){
      _available = true;
      _switch_to=0;
    }
    
    void set_unavailable(){
      _available = false;
      _switch_to=0;
    }
    
  };
  
  HashMap<EtherAddress,LocalIfInfo> get_if_list();

  typedef HashMap<EtherPair, DstInfo> RTable;
  typedef RTable::const_iterator RIter;

  RTable _rtable;

  typedef HashMap<int, LocalIfInfo> ITable;
  typedef ITable::const_iterator IIter;

  ITable _default_ifaces;
  
  typedef HashMap<EtherAddress, ChangingChannel> WarnTable;
  typedef WarnTable::const_iterator WIter;
  
  WarnTable _wtable;

private:
};

CLICK_ENDDECLS
#endif
