#ifndef CLICK_SR2LINKMETRICMULTI_HH
#define CLICK_SR2LINKMETRICMULTI_HH
#include <click/element.hh>
#include "sr2ettstatmulti.hh"
CLICK_DECLS

class SR2LinkMetricMulti : public Element {
 public:

  SR2LinkMetricMulti();
  virtual ~SR2LinkMetricMulti();

  const char *class_name() const { return "SR2LinkMetricMulti"; }
  const char *processing() const { return AGNOSTIC; }

  int configure(Vector<String> &, ErrorHandler *);

  virtual void update_link(NodeAddress, NodeAddress, 
			   Vector<SR2RateSize>, 
			   Vector<int>, Vector<int>, 
			   uint32_t);

 protected:

  class SR2LinkTableMulti *_link_table;

};

CLICK_ENDDECLS
#endif
