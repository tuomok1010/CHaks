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
    uint8_t* options;
};

#endif