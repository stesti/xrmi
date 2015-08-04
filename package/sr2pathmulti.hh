#ifndef CLICK_SR2PATHMULTI_HH
#define CLICK_SR2PATHMULTI_HH
#include <click/straccum.hh>
#include <click/hashcode.hh>
#include "sr2nodemulti.hh"
CLICK_DECLS

typedef Vector<NodeAirport> SR2PathMulti;

template <>
inline hashcode_t hashcode(const SR2PathMulti &p)
{
    hashcode_t h = 0;
    for (int x = 0; x < p.size(); x++)
	h ^= CLICK_NAME(hashcode)(p[x]);
    return h;
}

inline bool
operator==(const SR2PathMulti &p1, const SR2PathMulti &p2)
{
  if (p1.size() != p2.size()) {
    return false;
  }
  for (int x = 0; x < p1.size(); x++) {
    if (p1[x] != p2[x]) {
      return false;
    }
  }
  return true;
}

inline bool
operator!=(const SR2PathMulti &p1, const SR2PathMulti &p2)
{
  return (!(p1 == p2));
}

inline String path_to_string(const SR2PathMulti &p)
{
  StringAccum sa;
  for(int x = 0; x < p.size(); x++) {
    sa << p[x]._ipaddr << "," << p[x]._arr_iface << "," << p[x]._dep_iface;
    if (x != p.size() - 1) {
      sa << " ";
    }
  }
  return sa.take_string();
}


inline SR2PathMulti reverse_path (const SR2PathMulti &p)
{
  SR2PathMulti rev;
  for (int x = p.size() - 1; x >= 0; x--) {
    rev.push_back(p[x]);
  }
  return rev;
}


inline int index_of(SR2PathMulti p, IPAddress ip) {
  for (int x = 0;  x < p.size(); x++) {
    if (p[x]._ipaddr == ip) {
      return x;
    }
  }

  return -1;
}

CLICK_ENDDECLS
#endif /* CLICK_PATH_HH */
