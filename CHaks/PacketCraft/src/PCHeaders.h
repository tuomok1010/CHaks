#ifndef PC_HEADERS_H
#define PC_HEADERS_H

#include "PCTypes.h"

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

struct __attribute__ ((__packed__)) EthHeader
{
  uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
  uint16_t ether_type;		        /* packet type ID field	*/
};

struct __attribute__((__packed__)) ARPHeader
{
    uint16_t ar_hrd;		    /* Format of hardware address.  */
    uint16_t ar_pro;            /* Format of protocol address.  */
    uint8_t ar_hln;		        /* Length of hardware address.  */
    uint8_t ar_pln;		        /* Length of protocol address.  */
    uint16_t ar_op;		        /* ARP opcode (command).  */

    uint8_t ar_sha[ETH_ALEN];   /* Source hardware address */
    uint8_t ar_sip[IPV4_ALEN];  /* Source ipv4 address */
    uint8_t ar_tha[ETH_ALEN];   /* Target hardware address */
    uint8_t ar_tip[IPV4_ALEN];  /* Target ipv4 address */
};

struct __attribute__((__packed__)) IPv4Header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		    /* header length */
    unsigned int ip_v:4;		    /* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		    /* version */
    unsigned int ip_hl:4;		    /* header length */
#endif
    uint8_t ip_tos;			        /* type of service */
    unsigned short ip_len;		    /* total length */
    unsigned short ip_id;		    /* identification */
    unsigned short ip_off;		    /* fragment offset field */
    uint8_t ip_ttl;			        /* time to live */
    uint8_t ip_p;			        /* protocol */
    unsigned short ip_sum;		    /* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
    uint8_t options[];              /* optional options field */
};

struct __attribute__((__packed__)) IPv4OptionsHeader
{
    uint8_t copied:1;
    uint8_t opt_class:2;
    uint8_t opt_num:5;

    uint8_t opt_len;
    uint8_t opt_data[];
};

struct __attribute__((__packed__)) IPv6Header
{
    union
    {
        struct ip6_hdrctl
        {
            uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC, 20 bits flow-ID */
            uint16_t ip6_un1_plen;   /* payload length */
            uint8_t  ip6_un1_nxt;    /* next header */
            uint8_t  ip6_un1_hlim;   /* hop limit */
        } ip6_un1;

        uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
    } ip6_ctlun;

    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
};

struct __attribute__((__packed__)) ICMPv4Header
{
    uint8_t type;		/* message type */
    uint8_t code;		/* type sub-code */
    uint16_t checksum;
    union
    {
        struct
        {
            uint16_t	id;
            uint16_t	sequence;
        } echo;			/* echo datagram */
        uint32_t	gateway;	/* gateway address */
        struct
        {
            uint16_t	__glibc_reserved;
            uint16_t	mtu;
        } frag;			/* path mtu discovery */
    } un;

    uint8_t data[];
};

struct __attribute__((__packed__)) ICMPv6Header
{
    uint8_t     icmp6_type;   /* type field */
    uint8_t     icmp6_code;   /* code field */
    uint16_t    icmp6_cksum;  /* checksum field */

    uint8_t data[];
};

struct __attribute__((__packed__)) ICMPv6PseudoHeader
{
    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */

    uint32_t payloadLength;
    uint8_t zeroes[3];
    uint8_t nextHeader;
};

struct __attribute__((__packed__)) TCPHeader
{
    __extension__ union
    {
        struct
        {
            uint16_t th_sport;	/* source port */
            uint16_t th_dport;	/* destination port */
            tcp_seq th_seq;		/* sequence number */
            tcp_seq th_ack;		/* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
            uint8_t th_x2:4;	/* (unused) */
            uint8_t th_off:4;	/* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
            uint8_t th_off:4;	/* data offset */
            uint8_t th_x2:4;	/* (unused) */
# endif
            uint8_t th_flags;
            uint16_t th_win;	/* window */
            uint16_t th_sum;	/* checksum */
            uint16_t th_urp;	/* urgent pointer */
        };
        struct
        {
            uint16_t source;
            uint16_t dest;
            uint32_t seq;
            uint32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
            uint16_t res1:4;
            uint16_t doff:4;
            uint16_t fin:1;
            uint16_t syn:1;
            uint16_t rst:1;
            uint16_t psh:1;
            uint16_t ack:1;
            uint16_t urg:1;
            uint16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
            uint16_t doff:4;
            uint16_t res1:4;
            uint16_t res2:2;
            uint16_t urg:1;
            uint16_t ack:1;
            uint16_t psh:1;
            uint16_t rst:1;
            uint16_t syn:1;
            uint16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
            uint16_t window;
            uint16_t check;
            uint16_t urg_ptr;
        };
    };

    uint8_t optionsAndData[];
};

struct __attribute__((__packed__)) TCPv4PseudoHeader
{
    struct in_addr ip_src;  /* source address */
    struct in_addr ip_dst;	/* dest address */
    uint8_t zeroes;
    uint8_t proto;
    uint16_t tcpLen;
};

#endif