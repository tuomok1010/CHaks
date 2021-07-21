#ifndef PC_DEFINES_H
#define PC_DEFINES_H

#include <sys/types.h>
#include <stdint.h>

#define IPV4_ALEN 4
#define IPV6_ALEN 16

// NOTE: used as the default protocol in PacketCraft::Packet::ProcessReceivedPacket
#define PC_PROTO_ETH        UINT16_MAX

// PacketCraft::Packet layer types
// NOTE: if you add new ones, remember to update the networkProtocols variable in NetworkUtils.h
#define PC_NONE             0x0000
#define PC_ETHER_II         0x0001
#define PC_ARP              0x0002
#define PC_IPV4             0x0003
#define PC_IPV6             0x0004
#define PC_ICMPV4           0x0005
#define PC_ICMPV6           0x0006

#define PC_MAX_LAYERS       10

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

struct EthHeader;
struct ARPHeader;
struct IPv4Header;
struct IPv6Header;
struct ICMPv4Header;
struct ICMPv6Header;


#endif