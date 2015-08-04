#!/bin/sh 
#
# generate a roofnet config file for click
# John Bicket
# 
#

# Number of interfaces for this node
NUMBER_OF_INTERFACES=1

# The prefix for the device to be created and the displacement from zero
# (if DEV="ath" and DEV_DISPLACE=4, then the script will create ath4, ath5, ath6, ...)
DEV="ath"
DEV_DISPLACE=4
AVAILABLE_RATES="2 4 11 22";

DEBUG="true"
GATEWAY="false"
if [ -f /tmp/is_gateway ]; then
    GATEWAY="true"
    iptables -t nat -A POSTROUTING -j MASQUERADE
    echo 1 > /proc/sys/net/ipv4/ip_forward
fi

# extract the bottom three octects to use as IP
mac=$(/sbin/ifconfig wifi0 2>&1 | sed -n 's/^.*HWaddr \([0-9A-Za-z\-]*\).*/\1/p' | sed -e 's/\-/:/g' | cut -c1-17)
                            
hi_hex=$(echo $mac | sed -n 's/.*:.*:.*:\([0-9A-Za-z:]*\):.*:.*.*/\1/p')
mid_hex=$(echo $mac | sed -n 's/.*:.*:.*:.*:\([0-9A-Za-z:]*\):.*.*/\1/p')
lo_hex=$(echo $mac | sed -n 's/.*:.*:.*:.*:.*:\([0-9A-Za-z:]*\).*/\1/p')
                                                        
hi="0x$hi_hex";             
mid="0x$mid_hex";           
lo="0x$lo_hex";             

SUFFIX=$(($hi)).$(($mid)).$(($lo))
WIRELESS_MAC=$mac
SRCR2_IP="6.$SUFFIX"
SRCR2_NM="255.0.0.0"
SRCR2_NET="6.0.0.0"
SRCR2_BCAST="6.255.255.255"
WLANCONFIG=/sbin/wlanconfig

[ ! -f $WLANCONFIG ] && {
	echo "Couldn't find $WLANCONFIG";
	exit 1;	
}

if_id=1
for if_id in `seq 1 1 $NUMBER_OF_INTERFACES`; do
	if_fromzero=$(($if_id-1))
	device=wifi$if_fromzero
	DEV=ath$(($(($if_id-1))+$DEV_DISPLACE))
	$WLANCONFIG $DEV destroy > /dev/null 2>&1
	$WLANCONFIG $DEV create wlandev wifi0 wlanmode monitor > /dev/null 2>&1
	/sbin/ifconfig $DEV mtu 1900
	/sbin/ifconfig $DEV txqueuelen 5
	/sbin/ifconfig $DEV up
	echo '804' >  /proc/sys/net/$DEV/dev_type
	/sbin/modprobe tun > /dev/null 2>&1
	IFNAMES=${IFNAMES:+"$IFNAMES "}$DEV
done

if_id=1
for if_id in `seq 1 1 $NUMBER_OF_INTERFACES`; do
	if_fromzero=$(($if_id-1))
	device=wifi$if_fromzero
	macaddr=$(/sbin/ifconfig $device 2>&1 | sed -n 's/^.*HWaddr \([0-9A-Za-z\-]*\).*/\1/p' | sed -e 's/\-/:/g' | cut -c1-17)
	HWADDRS=${HWADDRS:+"$HWADDRS "}$macaddr
done

PROBES="2 62 2 1500 4 1500 11 1500 22 1500"
TX_RATE="22"

echo "interfaces :: AvailableInterfaces	(";

if_id=1
for i in $(seq 1 1 $NB_IFNAMES); do
  HWADDR=$(echo $HWADDRS | cut -d" " -f$i)
  IFNAME=$(echo $IFNAMES | cut -d" " -f$i)
  echo "DEFAULT $(($(($if_id*256))+1)) $IFNAME $HWADDR $AVAILABLE_RATES, ";
  if_id=$(($if_id+1))
done
echo ");

elementclass Sr2 {
  \$sr2_ip, \$sr2_nm, \$gateway, \$rate, \$debug, \$probes|


arp :: ARPTableMulti();
lt :: SR2LinkTableMulti(IP \$sr2_ip);

ifcl :: SR2ClassifierMulti(IT interfaces,
		  ARP arp, DEBUG \$debug, ISDEST "false");

ifclfw :: SR2ClassifierMulti(IT interfaces,
		  ARP arp, DEBUG \$debug, ISDEST "false");

";

if_id=1
for i in `echo ${HWADDRS} | tr ' ' '\n'`; do
if_fromzero=$(($if_id-1))
echo "route_encap_i$if_id :: WifiEncap(0x0, 00:00:00:00:00:00) -> FullNoteQueue(10) -> [$((2*$if_id-1))] output;
  ifclfw[$(($if_fromzero))]-> FullNoteQueue(10) -> WifiEncap(0x0, 00:00:00:00:00:00) -> [$((2*$if_id))] output;
	";
if_id=$(($if_id+1))
done

if_id=1
for i in `echo ${HWADDRS} | tr ' ' '\n'`; do
echo "
es_i$if_id :: SR2ETTStatMulti(ETHTYPE 0x0641, 
		  IP \$sr2_ip, 
		  IT interfaces,
		  ETH $i,			
		  PERIOD 30000,
		  TAU 300000,
		  ARP arp,
		  PROBES \$probes,
		  METRIC metric);

es_i$if_id -> SetTimestamp() -> route_encap_i$if_id;
";
if_id=$(($if_id+1))
done

echo "
data_ck :: SR2SetChecksumMulti()
  -> ifclfw

gw :: SR2GatewaySelectorMulti(ETHTYPE 0x062c,
		      IP \$sr2_ip,
		      IT interfaces,
		      LT lt,
		      ARP arp,
		      PERIOD 15000,
		      EXPIRE 30000,
		      GW \$gateway);

gw -> SR2SetChecksumMulti -> ifcl;

cas :: SR2ChannelSelectorMulti(ETHTYPE 0x062d,
                        IP \$sr2_ip,
                        IT interfaces,
                        LT lt,
                        ARP arp,
                        PERIOD 15000,
                        EXPIRE 30000,
                        CAS true);

cas_assign :: SR2ChannelAssignerMulti(ETHTYPE 0x62d,
                                   IP \$sr2_ip,
                                   LT lt,
                                   IT interfaces,
                                   ARP arp,
                                   PERIOD 600000,
                                   VERSION 1,
                                   DEBUG \$debug);
                                   
cas [0] -> SR2SetChecksumMulti -> ifcl;
cas [1] -> cas_assign -> SR2SetChecksumMulti -> ifcl;

";

if_id=1
for i in `echo ${HWADDRS} | tr ' ' '\n'`; do
	if_fromzero=$(($if_id-1))
	echo "ifcl[$(($if_fromzero))] -> route_encap_i$if_id;
	";
if_id=$(($if_id+1))
done

echo "
set_gw :: SR2SetGatewayMulti(SEL gw);


metric :: SR2ETTMetricMulti(LT lt);


forwarder :: SR2ForwarderMulti(ETHTYPE 0x0643, 
			      IP \$sr2_ip, 
			      IT interfaces,
			      LT lt, 
			      ARP arp);


querier :: SR2QuerierMulti(ETHTYPE 0x0644,
			IP \$sr2_ip, 
			IT interfaces,
			FWD forwarder,
			LT lt, 
			TIME_BEFORE_SWITCH 5,
			DEBUG \$debug);


query_forwarder :: SR2MetricFloodMulti(ETHTYPE 0x0644,
			       IP \$sr2_ip, 
			       IT interfaces,
			       LT lt, 
			       ARP arp,
			       DEBUG \$debug);


query_responder :: SR2QueryResponderMulti(ETHTYPE 0x0645,
				    IP \$sr2_ip, 
			        IT interfaces,
				    LT lt, 
				    ARP arp,
				    DEBUG \$debug);


gw_reply ::  SR2GatewayResponderMulti(SEL gw, 
				 ETHTYPE 0x0645,
				 IP \$sr2_ip,
			     IT interfaces,
				 ARP arp,
				 DEBUG \$debug,
				 LT lt,
				 PERIOD 15000);

"

for i in $(seq 2 1 $NB_IFNAMES); do
  HWADDR=$(echo $HWADDRS | cut -d" " -f$i)
  IFNAME=$(echo $IFNAMES | cut -d" " -f$i)
  echo "cas_reply_i$i ::  SR2ChannelResponderMulti(CHSEL cas, 
   				 ETHTYPE 0x062d,
   				 ETH $HWADDR,
   				 IP \$sr2_ip,
   				 LT lt,
   			   IT interfaces,
   				 ARP arp,
   				 WINFO winfo_i$i,
   				 CHSTR \"$IFNAME\",
   				 PERIOD 20000,
   				 CHANPERIOD 3000,
   				 COUNT counter_i$i,
   				 DEBUG \$debug);

"
done

for i in $(seq 2 1 $NB_IFNAMES); do
echo "cas_reply_i$i -> SR2SetChecksumMulti() -> ifcl;"
done

echo "

gw_reply -> SR2SetChecksumMulti() -> ifcl;
query_responder -> SR2SetChecksumMulti -> ifcl;
query_forwarder -> SR2SetChecksumMulti -> ifcl;

query_forwarder [1] -> query_responder;


input [1] 
-> host_cl :: IPClassifier(dst net \$sr2_ip mask \$sr2_nm, -)
-> querier
-> data_ck;


host_cl [1] -> [0] set_gw [0] -> querier;


forwarder[0] 
  -> dt ::DecIPTTL
  -> data_ck;


dt[1] 
-> ICMPError(\$sr2_ip, timeexceeded, 0) 
-> querier;


querier [1] -> SR2SetChecksumMulti -> ifcl;


forwarder[1] //ip packets to me
  -> SR2StripHeaderMulti()
  -> CheckIPHeader(CHECKSUM false)
  -> from_gw_cl :: IPClassifier(src net \$sr2_ip mask \$sr2_nm, -)
  -> [0] output;


from_gw_cl [1] -> [1] set_gw [1] -> [0] output;

chm1 :: SR2CheckHeaderMulti() -> forwarder;
chm2 :: SR2CheckHeaderMulti() -> query_forwarder;
chm3 :: SR2CheckHeaderMulti() -> query_responder;
chm4 :: SR2CheckHeaderMulti() -> gw;
chm5 :: SR2CheckHeaderMulti() -> cas;

"

if_id=1
for i in `echo ${HWADDRS} | tr ' ' '\n'`; do
if_fromzero=$(($if_id-1))
echo "input [$(($if_fromzero))]
  -> ncl_i$if_id :: Classifier(12/0643 , //sr2_forwarder
                       12/0644 , //sr2
                       12/0645 , //replies
                       12/0641 , //sr2_es
                       12/062c , //sr2_gw
                       12/062d , //sr2_cas
                       );
 
 
 ncl_i$if_id[0] -> chm1;
 ncl_i$if_id[1] -> chm2;
 ncl_i$if_id[2] -> chm3;
 ncl_i$if_id[3] -> es_i$if_id;
 ncl_i$if_id[4] -> chm4;
 ncl_i$if_id[5] -> chm5;
"
if_id=$(($if_id+1))
done



echo "

}

control :: ControlSocket(\"TCP\", 7777);

// has one input and one output
// takes and spits out ip packets
elementclass LinuxIPHost {
    \$dev, \$ip, \$nm |

  input -> KernelTun(\$ip/\$nm, MTU 1500, DEVNAME \$dev) 
  -> CheckIPHeader(CHECKSUM false)
  -> output;

}

elementclass SniffDevice {
    \$promisc|
";

if_id=1
for i in `echo ${IFNAMES} | tr ' ' '\n'`; do
	if_fromzero=$(($if_id-1))
	echo "from_dev_i$if_id :: FromDevice($i, PROMISC \$promisc) -> [$if_fromzero] output ;
input[$if_fromzero] -> to_dev_i$if_id :: ToDevice($i);";
	if_id=$(($if_id+1))
done

echo "
}

sniff_dev :: SniffDevice(false);

";

if_id=1
for i in `echo ${IFNAMES} | tr ' ' '\n'`; do
	if_fromzero=$(($if_id-1))
	echo "sched_i$if_id :: PrioSched() -> encap_i$if_id :: AthdescEncap() -> [$if_fromzero] sniff_dev;
	";
	if_id=$(($if_id+1))
done

echo "

srcr2 :: Sr2($SRCR2_IP, $SRCR2_NM, $GATEWAY, $TX_RATE, $DEBUG,
		 \"$PROBES\");

srcr2_host :: LinuxIPHost(srcr2, $SRCR2_IP, $SRCR2_NM)
-> [1] srcr2;

srcr2 [0] -> srcr2_host; 
";

if_id=1
for i in `echo ${IFNAMES} | tr ' ' '\n'`; do
	if_fromzero=$(($if_id-1))
	echo "srcr2 [$((2*$if_id-1))] -> [0] sched_i$if_id; // queries, replies, bcast_stats
srcr2 [$((2*$if_id))] -> [1] sched_i$if_id; // data
	";
	if_id=$(($if_id+1))
done

if_id=1
for i in `echo ${HWADDRS} | tr ' ' '\n'`; do
echo "
sniff_dev [$(($if_id-1))]

-> decap_i$if_id :: AthdescDecap()
-> phyerr_filter_i$if_id :: FilterPhyErr()
-> Classifier(0/08%0c) //data
-> tx_filter_i$if_id :: FilterTX()
-> dupe_i$if_id :: WifiDupeFilter() 
-> WifiDecap()
-> HostEtherFilter($i, DROP_OTHER true, DROP_OWN true) 
-> Classifier(12/06??)
-> [$((if_id-1))] srcr2;
";
if_id=$(($if_id+1))
done


echo "
gateway_enable :: Script(pause, write srcr2/gw.is_gateway true, loop);
gateway_disable :: Script(pause, write srcr2/gw.is_gateway false, loop);

";
