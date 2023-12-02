# goModifyPacket

Modifies a packet based on

https://github.com/AkihiroSuda/go-netfilter-queue

# redirect AMT traffic

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

## Discovery definition in the kernel

https://github.com/torvalds/linux/blob/3b47bc037bd44f142ac09848e8d3ecccc726be99/tools/testing/selftests/net/amt.sh#L4
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