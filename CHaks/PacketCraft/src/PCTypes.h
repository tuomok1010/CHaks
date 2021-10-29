#ifndef PC_DEFINES_H
#define PC_DEFINES_H

#include <sys/types.h>
#include <stdint.h>

#define IPV4_ALEN 4
#define IPV6_ALEN 16

#define FQDN_MAX_STR_LEN                255

// used when allocating buffers for printing different kinds of packet layers. Check PrintUDPLayer() in NetworkUtils for example
#define PC_ETH_MAX_STR_SIZE             5000
#define PC_ARP_MAX_STR_SIZE             5000
#define PC_IPV4_MAX_STR_SIZE            5'000
#define PC_IPV6_MAX_STR_SIZE            5'000
#define PC_ICMPV4_MAX_STR_SIZE          5'000
#define PC_ICMPV6_MAX_STR_SIZE          5'000
#define PC_TCP_MAX_STR_SIZE             20'000
#define PC_UDP_MAX_STR_SIZE             20'000
////////////////////////////////////////////////////

// used when converting packet layers into strings. Check ConvertUDPLayerToString in NetworkUtils for example
#define PC_ICMPV4_MAX_DATA_STR_SIZE     5000
#define PC_IPV4_MAX_OPTIONS_STR_SIZE    5000
#define PC_ICMPV6_MAX_DATA_STR_SIZE     5000
#define PC_TCP_MAX_OPTIONS_STR_SIZE     5000
#define PC_TCP_MAX_DATA_STR_SIZE        20'000
#define PC_UDP_MAX_DATA_STR_SIZE        20'000
#define PC_DNS_MAX_DATA_STR_SIZE        20'000
#define PC_DNS_MAX_Q_SECTION_STR_SIZE   5000
////////////////////////////////////////////////////



/*
    NOTE: PacketCraft::Packet layer types. These are the link/internet/transport layers that PacketCraft supports.
    If you add new ones, remember to update the networkProtocols variable in NetworkUtils.h
*/

// NOTE: used as the default protocol in PacketCraft::Packet::ProcessReceivedPacket
#define PC_PROTO_ETH        UINT16_MAX

// Supported link/internet layer protocols
#define PC_NONE             0x0000
#define PC_ETHER_II         0x0001
#define PC_ARP              0x0002
#define PC_IPV4             0x0003
#define PC_IPV6             0x0004

// Supported payload protocols
#define PC_ICMPV4           0x0005
#define PC_ICMPV6           0x0006
#define PC_TCP              0x0007
#define PC_TCP_OPTIONS      0x0008
#define PC_UDP              0x0009

// Supported application layer protocols. Used in NetworkUtils GetTCPDataProtocol and GetUDPDataProtocol
#define PC_HTTP             0x000a
#define PC_DNS              0x000b
/////////////////////////////////////////////////////



#define PC_MAX_LAYERS       10

#define TRUE                1
#define FALSE               0

#define NO_ERROR            0
#define APPLICATION_ERROR   1

#define ETH_ADDR_STR_LEN    18

typedef int32_t bool32;

enum class PingType
{
    ECHO_REQUEST,
    ECHO_REPLY
};

enum class IPVersion
{
    NONE,
    IPV4,
    IPV6
};

struct ether_addr;
struct sockaddr_in;
struct sockaddr_in6;
struct sockaddr_storage;
struct sockaddr;

struct EthHeader;
struct ARPHeader;
struct IPv4Header;
struct IPv4OptionsHeader;
struct IPv6Header;
struct ICMPv4Header;
struct ICMPv6Header;
struct TCPHeader;
struct UDPHeader;
struct DNSHeader;
struct TCPv4PseudoHeader;
struct UDPv4PseudoHeader;

#endif