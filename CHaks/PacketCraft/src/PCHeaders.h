#ifndef PC_HEADERS_H
#define PC_HEADERS_H

#include "PCTypes.h"

#include <netinet/if_ether.h>
#include <netinet/in.h>

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
    uint8_t options[];              /* optional options field, NOTE: when doing sizeof() this struct, this will not count (C magic)*/
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

#endif