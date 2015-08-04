#ifndef SR2ETTMETRICMULTI_HH
#define SR2ETTMETRICMULTI_HH
#include <click/element.hh>
#include "sr2linkmetricmulti.hh"
#include <click/hashmap.hh>
#include <click/etheraddress.hh>
#include <clicknet/wifi.h>
#include "sr2ettstatmulti.hh"
#include <elements/wifi/bitrate.hh>
CLICK_DECLS

/*
 * =c
 * SR2ETTMetric
 * =s Wifi
 * Estimated Transmission Time (ETT) metric
 * 
 * =io
 * None
 *
 */

inline unsigned sr2_ett_metric(int ack_prob, int data_prob, int data_rate) 
{
  
  if (!ack_prob || ! data_prob || ack_prob < 30 || data_prob < 30) {
    return 999999;
  }

  int retries = 100 * 100 * 100 / (ack_prob * data_prob) - 100;
  unsigned low_usecs = calc_usecs_wifi_packet(1500, data_rate, retries/100);
  unsigned high_usecs = calc_usecs_wifi_packet(1500, data_rate, (retries/100) + 1);

  unsigned diff = retries % 100;
  unsigned average = (diff * high_usecs + (100 - diff) * low_usecs) / 100;
  return average;

}

class SR2ETTMetricMulti : public SR2LinkMetricMulti {
  
public:

  SR2ETTMetricMulti();
  ~SR2ETTMetricMulti();
  const char *class_name() const { return "SR2ETTMetricMulti"; }
  void *cast(const char *);
  const char *processing() const { return AGNOSTIC; }

  void update_link(NodeAddress from, NodeAddress to, 
		   Vector<SR2RateSize> rs, 
		   Vector<int> fwd, Vector<int> rev, 
		   uint32_t seq);

};

CLICK_ENDDECLS
#endif
