#ifndef SR2TXCOUNTMETRICMULTI_HH
#define SR2TXCOUNTMETRICMULTI_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/etheraddress.hh>
#include <clicknet/wifi.h>
#include <elements/wifi/bitrate.hh>
#include "sr2txcountmetricmulti.hh"
#include "sr2linkmetricmulti.hh"
CLICK_DECLS

/*
 * =c
 * SR2TXCountMetricMulti
 * =s Wifi
 * Estimated Transmission Count metric (ETX).
 * 
 * =io
 * None
 *
 */

inline unsigned sr2_etx_metric(int ack_prob, int data_prob) 
{
  
  if (!ack_prob || ! data_prob || ack_prob < 30 || data_prob < 30) {
    return 9999;
  }

  return 100 * 100 * 100 / (ack_prob * data_prob) - 100;

}

class SR2TXCountMetricMulti : public SR2LinkMetricMulti {
  
public:

  SR2TXCountMetricMulti();
  ~SR2TXCountMetricMulti();
  const char *class_name() const { return "SR2TXCountMetricMulti"; }
  void *cast(const char *);
  const char *processing() const { return AGNOSTIC; }

  void update_link(NodeAddress from, NodeAddress to, 
		   Vector<SR2RateSize> rs, 
		   Vector<int> fwd, Vector<int> rev, 
		   uint32_t seq);

};

CLICK_ENDDECLS
#endif
