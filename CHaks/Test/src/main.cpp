#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

#include <iostream>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>
#include <cstring>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>

// IPv4PingPacket test

void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name>\n\n"
        << "<interface name>: the interface you wish to sent the packets from.\n"
        << std::endl;
}

// TODO: make this more bulletproof
int ProcessArgs(int argc, char** argv, char* ifName)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }
    
    if(argc != 2)
    {
        LOG_ERROR(APPLICATION_ERROR, "invalid args error!");
        return APPLICATION_ERROR;
    }

    if(PacketCraft::GetStrLen(argv[1]) > IFNAMSIZ)
    {
        LOG_ERROR(APPLICATION_ERROR, "invalid args error!");
        return APPLICATION_ERROR;
    }

    PacketCraft::CopyStr(ifName, IFNAMSIZ, argv[1]);

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char ifName[IFNAMSIZ]{};
    if(ProcessArgs(argc, argv, ifName) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }

    int socketFd = socket(PF_PACKET, SOCK_RAW, htons(IPPROTO_IPV6));
    if(socketFd == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    char myIP[INET6_ADDRSTRLEN]{};
    if(PacketCraft::GetIPAddr(myIP, ifName, AF_INET6) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "GetIPAddr() error!");
        return APPLICATION_ERROR;
    }

    char myMAC[ETH_ADDR_STR_LEN]{};
    if(PacketCraft::GetMACAddr(myMAC, ifName, socketFd) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "GetMACAddr() error!");
        return APPLICATION_ERROR;
    }

    PacketCraft::IPv6PingPacket pingPacket;
    pingPacket.Create(myMAC, "00:00:00:00:00:00", myIP, "::1", PingType::ECHO_REQUEST);

    char buffer[1000]{};
    ICMPv6Header* icmpv6Header = (ICMPv6Header*)pingPacket.GetLayerStart(2);
    IPv6Header* ipv6Header = (IPv6Header*)pingPacket.GetLayerStart(1);

    uint32_t icmpv6DataSize = PacketCraft::CalculateICMPv6DataSize(ipv6Header, icmpv6Header);
    PacketCraft::ConvertICMPv6LayerToString(buffer, 1000, icmpv6Header, icmpv6DataSize);

    std::cout << "BUFFER:\n\n" << buffer << std::endl;

    std::cout << "data size was: " << icmpv6DataSize << std::endl;

    close(socketFd);

    return NO_ERROR;
}