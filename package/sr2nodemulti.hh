#ifndef CLICK_SR2NODEMULTI_HH
#define CLICK_SR2NODEMULTI_HH
#include <click/ipaddress.hh>
CLICK_DECLS

class NodeAddress{
  public:
	
	IPAddress _ipaddr;
	uint16_t _iface;
	
	NodeAddress()
	: _ipaddr(IPAddress()), _iface(0){
	}
	
	NodeAddress(IPAddress ipaddr, uint16_t iface)
	: _ipaddr(ipaddr), _iface(iface){
	}

	typedef uint32_t (NodeAddress::*unspecified_bool_type)() const;
	/** @brief Return true iff the address is not 0.0.0.0. */
	inline operator unspecified_bool_type() const {
	return _ipaddr.addr() != 0 ? &NodeAddress::addr : 0;
	}

	/** @brief Return the address as a uint32_t in network byte order. */
	inline operator uint32_t() const
	{
	    return _ipaddr.addr();
	}

	/** @brief Return the address as a uint32_t in network byte order. */
	inline uint32_t addr() const
	{
	    return _ipaddr.addr();

	}

	inline uint32_t
	hashcode() const
	{
	    return _ipaddr.addr();
	}

	inline bool operator==(NodeAddress other) const {
	return (other._ipaddr == _ipaddr && other._iface == _iface);
    	}

	inline bool operator!=(NodeAddress other) const {
	return (other._ipaddr != _ipaddr || other._iface != _iface);
    	}
	
};

class NodeAirport{
  public:
	
	IPAddress _ipaddr;
	uint16_t _arr_iface;
	uint16_t _dep_iface;
	
	NodeAirport()
	: _ipaddr(IPAddress()), _arr_iface(0), _dep_iface(0) {
	}
	
	NodeAirport(IPAddress ipaddr, uint16_t arr_iface, uint16_t dep_iface)
	: _ipaddr(ipaddr), _arr_iface(arr_iface), _dep_iface(dep_iface){
	}

	//NodeAddress get_arr_hub(){ return NodeAddress(_ipaddr, _arr_iface); }
	
	//NodeAddress get_dep_hub(){ return NodeAddress(_ipaddr, _dep_iface); }

	NodeAirport set_arr(NodeAddress *p){ return NodeAirport(p->_ipaddr,p->_iface,0); }

	NodeAirport set_dep(NodeAddress *p){ return NodeAirport(p->_ipaddr,0,p->_iface); }
	
	NodeAddress get_arr(){ return NodeAddress(_ipaddr,_arr_iface); }

	NodeAddress get_dep(){ return NodeAddress(_ipaddr,_dep_iface); }

	inline uint32_t
	hashcode() const
	{
	    return _ipaddr.addr();
	}

	inline bool operator==(NodeAirport other) const {
	return (other._ipaddr == _ipaddr && other._arr_iface == _arr_iface && other._dep_iface == _dep_iface);
    	}

	inline bool operator!=(NodeAirport other) const {
	return (other._ipaddr != _ipaddr || other._arr_iface != _arr_iface || other._dep_iface != _dep_iface);
    	}
	
};

CLICK_ENDDECLS
#endif /* CLICK_SR2NODEMULTI_HH */
