# goModifyPacket

Modifies a packet based on

https://github.com/AkihiroSuda/go-netfilter-queue

# redirect AMT traffic

Ended up putting the NFQUEUE rule in the prerouting table

:PREROUTING ACCEPT [0:0]
-A PREROUTING -i wlp0s20f3 -p udp --sport 2268 -j NFQUEUE --queue-num 0

Should also work for input
iptables -A INPUT -p udp --dport 2268 -j NFQUEUE --queue-num 0

# Automatic Multicast Tunnel RFC

AMT RFC
https://www.rfc-editor.org/rfc/rfc7450.html

DNS related to AMT
https://www.rfc-editor.org/rfc/rfc8777

## Discovery definition

https://www.rfc-editor.org/rfc/rfc7450.html#section-5.1.2

We are aiming to change the IP address in the Relay Advertisement

```bash
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  V=0  |Type=2 |                   Reserved                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Discovery Nonce                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                  Relay Address (IPv4 or IPv6)                 ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 12: Relay Advertisement Message Format
```

## Kernel AMT code

https://github.com/torvalds/linux/blob/master/drivers/net/amt.c
https://github.com/torvalds/linux/blob/master/include/net/amt.h


Tests
https://github.com/torvalds/linux/blob/master/tools/testing/selftests/net/amt.sh

## Discovery definition in the kernel

https://github.com/torvalds/linux/blob/master/include/net/amt.h#L120
```bash
struct amt_header_advertisement {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u32	type:4,
		version:4,
		reserved:24;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u32	version:4,
		type:4,
		reserved:24;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__be32	nonce;
	__be32	ip4;
} __packed;
```


## Multicast Listener Discovery Version 2 (MLDv2) for IPv6

https://www.rfc-editor.org/rfc/rfc3810



## RFC improvements

There should be an option 2, which would mean both IPv4 IGMPv3 and IPv6 MLDv2.

5.1.3.4.  P Flag

   The P flag is set to indicate which group membership protocol the
   gateway wishes the relay to use in the Membership Query response:

   Value   Meaning

     0     The relay MUST respond with a Membership Query message that
           contains an IPv4 packet carrying an IGMPv3 General Query
           message.
     1     The relay MUST respond with a Membership Query message that
           contains an IPv6 packet carrying an MLDv2 General Query
           message.

## Sysctls

```bash
das@t:~/Downloads/tunnel$ sysctl -a 2>&1 | grep amtg
net.ipv4.conf.amtg.accept_local = 0
net.ipv4.conf.amtg.accept_redirects = 1
net.ipv4.conf.amtg.accept_source_route = 0
net.ipv4.conf.amtg.arp_accept = 0
net.ipv4.conf.amtg.arp_announce = 0
net.ipv4.conf.amtg.arp_evict_nocarrier = 1
net.ipv4.conf.amtg.arp_filter = 0
net.ipv4.conf.amtg.arp_ignore = 0
net.ipv4.conf.amtg.arp_notify = 0
net.ipv4.conf.amtg.bc_forwarding = 0
...

```

```bash
das@t:/proc/sys/net/ipv4/conf/amtg$ ls -la
total 0
dr-xr-xr-x 1 root root 0 Dec  2 11:21 .
dr-xr-xr-x 1 root root 0 Nov 27 11:32 ..
-rw-r--r-- 1 root root 0 Dec  2 13:20 accept_local
-rw-r--r-- 1 root root 0 Dec  2 13:20 accept_redirects
-rw-r--r-- 1 root root 0 Dec  2 11:21 accept_source_route
-rw-r--r-- 1 root root 0 Dec  2 13:20 arp_accept
-rw-r--r-- 1 root root 0 Dec  2 13:20 arp_announce
-rw-r--r-- 1 root root 0 Dec  2 13:20 arp_evict_nocarrier
-rw-r--r-- 1 root root 0 Dec  2 13:20 arp_filter
-rw-r--r-- 1 root root 0 Dec  2 13:20 arp_ignore
-rw-r--r-- 1 root root 0 Dec  2 13:20 arp_notify
-rw-r--r-- 1 root root 0 Dec  2 13:20 bc_forwarding
-rw-r--r-- 1 root root 0 Dec  2 13:20 bootp_relay
-rw-r--r-- 1 root root 0 Dec  2 13:20 disable_policy
-rw-r--r-- 1 root root 0 Dec  2 13:20 disable_xfrm
-rw-r--r-- 1 root root 0 Dec  2 13:20 drop_gratuitous_arp
-rw-r--r-- 1 root root 0 Dec  2 13:20 drop_unicast_in_l2_multicast
-rw-r--r-- 1 root root 0 Dec  2 13:20 force_igmp_version
-rw-r--r-- 1 root root 0 Dec  2 13:20 forwarding
-rw-r--r-- 1 root root 0 Dec  2 13:20 igmpv2_unsolicited_report_interval
-rw-r--r-- 1 root root 0 Dec  2 13:20 igmpv3_unsolicited_report_interval
-rw-r--r-- 1 root root 0 Dec  2 13:20 ignore_routes_with_linkdown
-rw-r--r-- 1 root root 0 Dec  2 13:20 log_martians
-r--r--r-- 1 root root 0 Dec  2 13:20 mc_forwarding
-rw-r--r-- 1 root root 0 Dec  2 13:20 medium_id
-rw-r--r-- 1 root root 0 Dec  2 11:21 promote_secondaries
-rw-r--r-- 1 root root 0 Dec  2 13:20 proxy_arp
-rw-r--r-- 1 root root 0 Dec  2 13:20 proxy_arp_pvlan
-rw-r--r-- 1 root root 0 Dec  2 13:20 route_localnet
-rw-r--r-- 1 root root 0 Dec  2 11:21 rp_filter
-rw-r--r-- 1 root root 0 Dec  2 13:20 secure_redirects
-rw-r--r-- 1 root root 0 Dec  2 13:20 send_redirects
-rw-r--r-- 1 root root 0 Dec  2 13:20 shared_media
-rw-r--r-- 1 root root 0 Dec  2 13:20 src_valid_mark
-rw-r--r-- 1 root root 0 Dec  2 13:20 tag
```

AMT Timing related sysctls

```
net.ipv4.conf.amtg.igmpv2_unsolicited_report_interval = 10000
net.ipv4.conf.amtg.igmpv3_unsolicited_report_interval = 1000

net.ipv4.neigh.amtg.base_reachable_time_ms = 30000
net.ipv4.neigh.amtg.delay_first_probe_time = 5
net.ipv4.neigh.amtg.gc_stale_time = 60
net.ipv4.neigh.amtg.interval_probe_time_ms = 5000
net.ipv4.neigh.amtg.locktime = 100
```

## Interface

```bash
das@t:~/Downloads/tunnel$ ifconfig amtg
amtg: flags=4098<BROADCAST,MULTICAST>  mtu 1450
        ether fa:c2:bc:79:68:5b  txqueuelen 1000  (Ethernet)
        RX packets 2042  bytes 114352 (114.3 KB)
        RX errors 0  dropped 10  overruns 0  frame 0
        TX packets 2066  bytes 169368 (169.3 KB)
        TX errors 725  dropped 2433 overruns 0  carrier 0  collisions 0
```