#ifndef CLICK_SR2PACKETMULTI_HH
#define CLICK_SR2PACKETMULTI_HH
#include <click/ipaddress.hh>
#include "sr2pathmulti.hh"
#include "sr2nodemulti.hh"
CLICK_DECLS

enum sr2packetmulti_type { 
	SR2_PT_QUERY = 0x01,
	SR2_PT_REPLY = 0x02,
	SR2_PT_DATA  = 0x04,
	SR2_PT_GATEWAY = 0x08,
	SR2_PT_PROBE = 0x16,
	SR2_PT_CHBEACON = 0x32,
	SR2_PT_CHSCINFO = 0x33,
	SR2_PT_CHASSIGN = 0x34,
	SR2_PT_CHNGWARN = 0x35,
};


enum sr2packetmulti_flags {
	SR2_FLAG_ERROR = (1<<0),
	SR2_FLAG_UPDATE = (1<<1),
};

enum link_probe_flags {
	PROBE_AVAILABLE_RATES = (1<<0),
	PROBE_LINK_ENTRIES = (1<<1),
};

static const uint8_t _sr2_version = 0x1c;

/* sr2cr packet format */
CLICK_PACKED_STRUCTURE(
struct sr2packetmulti {,
	uint8_t _version; /* see protocol version */
	uint8_t _type;    /* see protocol type */
	uint8_t _nlinks;
	uint8_t _next;    /* who should process this packet. */

	int    num_links()              { return _nlinks; }
	int    next()                   { return _next; }
	void   set_next(uint8_t n)      { _next = n; }
	void   set_num_links(uint8_t n) { _nlinks = n; }

	/* packet length functions */
	static size_t len_wo_data(int nlinks) {
		if (nlinks == 0) {
			return sizeof(struct sr2packetmulti) + sizeof(uint32_t) * 2;
		} else {
			return sizeof(struct sr2packetmulti) + sizeof(uint32_t) + 
				(nlinks) * sizeof(uint32_t) * 7;
		}
	}
	static size_t len_with_data(int nlinks, int dlen) {
		return len_wo_data(nlinks) + dlen;
	}
	size_t hlen_wo_data()   const { return len_wo_data(_nlinks); }
	size_t hlen_with_data() const { return len_with_data(_nlinks, ntohs(_dlen)); }

private:
	/* these are private and have access functions below so I
	 * don't have to remember about endianness
	 */
	uint16_t _ttl;
	uint16_t _cksum;
	uint16_t _flags; 
	uint16_t _dlen;

	uint32_t _qdst; /* query destination */
	uint32_t _seq;
public:  
	bool      flag(int f) { return ntohs(_flags) & f;  }
	uint16_t  data_len()  { return ntohs(_dlen); }
	IPAddress qdst()      { return _qdst; }
	uint32_t  seq()       { return ntohl(_seq); }

	void      set_flag(uint16_t f)       { _flags = htons(ntohs(_flags) | f); }
	void      unset_flag(uint16_t f)     { _flags = htons(ntohs(_flags) & !f);  }
	void      set_data_len(uint16_t len) { _dlen = htons(len); }
	void      set_qdst(IPAddress ip)     { _qdst = ip; }
	void      set_seq(uint32_t n)        { _seq = htonl(n); }			

	/* remember that if you call this you must have set the number
	 * of links in this packet!
	 */
	u_char *data() { return (((u_char *)this) + len_wo_data(num_links())); }

	void set_checksum() {
		unsigned int tlen = (_type & SR2_PT_DATA) ? hlen_with_data() : hlen_wo_data();
		_cksum = click_in_cksum((unsigned char *) this, tlen);
	}

	bool check_checksum() {
		unsigned int tlen = (_type & SR2_PT_DATA) ? hlen_with_data() : hlen_wo_data();
		return click_in_cksum((unsigned char *) this, tlen) == 0;
	}

	/* the rest of the packet is variable length based on _nlinks.
	 * for each link, the following packet structure exists: 
	 * uint32_t ip
	 * uint32_t fwd
	 * uint32_t rev
	 * uint32_t seq
	 * uint32_t age
	 * uint32_t ip
	 * uint32_t ifa
     * uint32_t ifb
	 */
	void set_link(int link,
		      NodeAddress a, NodeAddress b, 
		      uint32_t fwd, uint32_t rev,
		      uint32_t seq,
		      uint32_t age) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		uint32_t ifa = a._iface;
		uint32_t ifb = b._iface;
		ndx[0] = a._ipaddr;
		ndx[1] = htonl(ifa);
		ndx[2] = htonl(fwd);
		ndx[3] = htonl(rev);
		ndx[4] = htonl(seq);
		ndx[5] = htonl(age);	
		ndx[6] = htonl(ifb);
		ndx[7] = b._ipaddr;
	}	
	uint32_t get_link_fwd(int link) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		return ntohl(ndx[2]);
	}
	uint32_t get_link_rev(int link) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		return ntohl(ndx[3]);
	}
	uint32_t get_link_seq(int link) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		return ntohl(ndx[4]);
	}
	
	uint32_t get_link_age(int link) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		return ntohl(ndx[5]);
	}	
	IPAddress get_link_node(int link) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		return ndx[0];
	}
	uint32_t get_link_if(int link) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		return ntohl(ndx[1]);
	}
	uint32_t get_link_if_b(int link) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		return ntohl(ndx[6]);
	}
	IPAddress get_link_node_b(int link) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		return ndx[7];
	}
	void set_link_node(int link, IPAddress a) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		ndx[0] = a;
	}
	void set_link_if(int link, uint16_t ifa) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		uint32_t if_a = ifa;
		ndx[1] = htonl(if_a);
	}
	void set_link_if_b(int link, uint16_t ifb) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		uint32_t if_b = ifb;
		ndx[6] = htonl(if_b);
	}
	void set_link_node_b(int link, IPAddress b) {
		uint32_t *ndx = (uint32_t *) (this+1);
		ndx += link * 7;
		ndx[7] = b;
	}
	SR2PathMulti get_path() {
		int x;
		SR2PathMulti p;
		p.push_back(NodeAirport(get_link_node_b(0),0,get_link_if_b(0)));
		for (x = 0; x < num_links(); x++) {
			p.push_back(NodeAirport(get_link_node(x),get_link_if(x),get_link_if_b(x+1)));
		}
		p.push_back(NodeAirport(get_link_node(x),get_link_if(x),0));
		return p;
	}
});

/* probe packet format */
CLICK_PACKED_STRUCTURE(struct link_info {,
	uint16_t size() { return ntohs(_size); }
	uint16_t rate() { return ntohs(_rate); }
	uint16_t fwd()  { return ntohs(_fwd); }
	uint16_t rev()  { return ntohs(_rev); }
	void set_size(uint16_t size)  { _size = htons(size); }
	void set_rate(uint16_t rate)  { _rate = htons(rate); }
	void set_fwd(uint16_t fwd)    { _fwd = htons(fwd); }
	void set_rev(uint16_t rev)    { _rev = htons(rev); }
  private:
	uint16_t _size;
	uint16_t _rate;
	uint16_t _fwd;
	uint16_t _rev;
});

CLICK_PACKED_STRUCTURE(struct rate_entry {,
	uint32_t rate() { return ntohs(_rate); }
	void set_rate(uint32_t rate)  { _rate = htons(rate); }
  private:
	uint32_t _rate;
});

CLICK_PACKED_STRUCTURE(struct link_entry_multi {,
	NodeAddress node()     { return NodeAddress(_ipaddr,_iface); }
	uint32_t num_rates()   { return ntohl(_num_rates); }
	uint32_t seq()         { return ntohl(_seq); }
	uint32_t age()         { return ntohl(_age); }
	void set_node(NodeAddress node)         { _ipaddr = node._ipaddr; _iface = node._iface; }
	void set_num_rates(uint32_t num_rates)  { _num_rates = htonl(num_rates); }
	void set_seq(uint32_t seq)              { _seq = htonl(seq); }
	void set_age(uint32_t age)              { _age = htonl(age); }
  private:
	uint32_t _ipaddr;
	uint16_t _iface;
	uint32_t _num_rates;
	uint32_t _seq;
	uint32_t _age;
});

CLICK_PACKED_STRUCTURE(struct channel_warn {,
  uint8_t _version; /* see protocol version */
	uint8_t _type;    /* see protocol type */
	private:
	uint8_t _hops;
  bool _status;
	uint32_t _origin;
	uint16_t _old_iface;
	uint16_t _new_iface;
  public:
  uint8_t hops()      { return _hops; }
	uint32_t origin()      { return _origin; }
  uint16_t old_iface()    { return _old_iface; }
  uint16_t new_iface()    { return _new_iface; }
  bool get_status()     { return _status; }
  void set_warn (IPAddress origin, uint16_t old_iface, uint16_t new_iface, bool status) {_origin = origin; _old_iface = old_iface; _new_iface = new_iface; _status = status; }
  void set_hops (int hops)    { _hops = hops; }
  void new_hop ()      { _hops++; }
});

CLICK_PACKED_STRUCTURE(struct link_probe_multi {,
  uint8_t _version; /* see protocol version */
	uint8_t _type;    /* see protocol type */
  private:
	uint16_t _cksum;     // internal checksum
	uint16_t _rate;
	uint16_t _size;
	uint32_t _ipaddr;
	uint32_t _iface;
	uint32_t _flags;
	uint32_t _seq;
	uint32_t _period;      // period of this node's probe broadcasts, in msecs
	uint32_t _tau;         // this node's loss-rate averaging period, in msecs
	uint32_t _sent;        // how many probes this node has sent
	uint32_t _num_probes;
	uint32_t _num_links;   // number of wifi_link_entry entries following
	uint32_t _num_rates;   // number of rate_entry entries following
  public:
	uint16_t rate() { return ntohs(_rate); }
	uint16_t size() { return ntohs(_size); }
	void set_rate(uint16_t rate)  { _rate = htons(rate); }
	void set_size(uint16_t size)  { _size = htons(size); }
	NodeAddress node()     { return NodeAddress(_ipaddr, _iface); }
	uint32_t seq()         { return ntohl(_seq); }
	uint32_t period()      { return ntohl(_period); }
	uint32_t tau()         { return ntohl(_tau); }
	uint32_t sent()        { return ntohl(_sent); }
	uint32_t num_probes()  { return ntohl(_num_probes); }
	uint32_t num_links()   { return ntohl(_num_links); }
	uint32_t num_rates()   { return ntohl(_num_rates); }
	void set_node(NodeAddress node)          { _ipaddr = node._ipaddr; _iface = node._iface; }
	void set_seq(uint32_t seq)               { _seq = htonl(seq); }
	void set_period(uint32_t period)         { _period = htonl(period); }
	void set_tau(uint32_t tau)               { _tau = htonl(tau); }
	void set_sent(uint32_t sent)             { _sent = htonl(sent); }
	void set_num_probes(uint32_t num_probes) { _num_probes = htonl(num_probes); }
	void set_num_links(uint32_t num_links)   { _num_links = htonl(num_links); }\
	void set_num_rates(uint32_t num_rates)   { _num_rates = htonl(num_rates); }
	bool flag(int f)                { return ntohs(_flags) & f;  }
	void set_flag(uint16_t f)       { _flags = htons(ntohs(_flags) | f); }
	void unset_flag(uint16_t f)     { _flags = htons(ntohs(_flags) & !f);  }
	void set_checksum() {
		_cksum = click_in_cksum((unsigned char *) this, sizeof(link_probe_multi));
	}	
	bool check_checksum() {
		return click_in_cksum((unsigned char *) this, sizeof(link_probe_multi)) == 0;
	}
});


CLICK_ENDDECLS
#endif /* CLICK_SR2PACKET_HH */
