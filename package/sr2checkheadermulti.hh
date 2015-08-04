#ifndef CLICK_SR2CHECKHEADERMULTI_HH
#define CLICK_SR2CHECKHEADERMULTI_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/glue.hh>
CLICK_DECLS

/*
 * =c
 * SR2CheckHeaderMulti()
 * =s Wifi, Wireless Routing
 * Check the Source Route header of a packet.
 * =d
 * Expects SR packets as input. Checks that the packet's 
 * length is reasonable, and that the SR header length, 
 * length, and checksum fields are valid. 
 * =a SR2SetChecksum
 */

class SR2CheckHeaderMulti : public Element {

 public:
  
  SR2CheckHeaderMulti();
  ~SR2CheckHeaderMulti();
  
  const char *class_name() const		{ return "SR2CheckHeaderMulti"; }
  const char *port_count() const		{ return "1/1-2"; }
  const char *processing() const		{ return "a/ah"; }

  int configure(Vector<String> &, ErrorHandler *);
  void add_handlers();

  Packet *simple_action(Packet *);

  int drops() const				{ return _drops; }
  String bad_nodes();

private:

  typedef HashMap<EtherAddress, uint8_t> BadTable;
  typedef BadTable::const_iterator BTIter;
  
  BadTable _bad_table;
  int _drops;
  bool _checksum;

  static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
