#ifndef PC_DEFINES_H
#define PC_DEFINES_H

#include <sys/types.h>

#define IPV4_ALEN 4
#define IPV6_ALEN 16

// PacketCraft::Packet layer types
#define PC_NONE             0x000000
#define PC_ETHER_II         0x000001
#define PC_ARP              0x000002
#define PC_IPV4             0x000003

#define PC_MAX_LAYERS       100

#define TRUE                1
#define FALSE               0

#define NO_ERROR            0
#define APPLICATION_ERROR   1

#define ETH_ADDR_STR_LEN    18

typedef int32_t bool32;

struct ether_addr;
struct sockaddr_in;
struct sockaddr_in6;
struct sockaddr_storage;
struct sockaddr;

struct ether_header;
struct ip;
struct icmphdr;


#endif