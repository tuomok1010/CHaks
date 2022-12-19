#include "DNSSpoofer.h"

#include <iostream>

#include <net/if.h>
#include <unistd.h>
#include <cstring>

bool32 FilterPacket(const PacketCraft::Packet& packet)
{
    std::cout << "in FilterPacket()" << std::endl;
    IPv4Header* ipv4Header = (IPv4Header*)packet.FindLayerByType(PC_IPV4);
    IPv6Header* ipv6Header = (IPv6Header*)packet.FindLayerByType(PC_IPV6);
    UDPHeader* udpHeader = (UDPHeader*)packet.FindLayerByType(PC_UDP);
    DNSHeader* dnsHeader = (DNSHeader*)packet.FindLayerByType(PC_DNS_RESPONSE);

    if(ipv4Header)
    {
        if(ipv4Header->ip_p == IPPROTO_UDP)
        {
            if(dnsHeader)
            {
                
            }
        }
        else if(ipv4Header->ip_p == IPPROTO_TCP)
        {
            if(dnsHeader)
            {
                if(dnsHeader->qr == 1)
                {
                    // TODO: support DNS over TCP
                    LOG_ERROR(APPLICATION_ERROR, "DNS over TCP not supported");
                    return FALSE;
                }
            }
            else
            {
                return FALSE;
            }
        }
    }
    else if(ipv6Header)
    {
        if(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP)
        {
            if(dnsHeader)
            {
                if(dnsHeader->qr == 1)
                {
                    // TODO: support IPV6
                    LOG_ERROR(APPLICATION_ERROR, "IPV6 not supported");
                    return FALSE;
                }
            }
        }
        else if(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP)
        {
            if(dnsHeader)
            {
                if(dnsHeader->qr == 1)
                {
                    // TODO: support DNS over TCP
                    LOG_ERROR(APPLICATION_ERROR, "DNS over TCP not supported");
                    return FALSE;
                }
            }
        }
    }
}

uint32_t EditPacket(PacketCraft::Packet& packet)
{
    std::cout << "in EditPacket()" << std::endl;
    return NO_ERROR;
}

void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <target ip> <fake domain ip> <domain>\n\n"
        << "<interface name>: the interface you wish to use.\n"
        << "<ip version>: ip version of the target, must be 4 or 6\n"
        << "<queueNum>: nft queue number used to capture packets\n"
        << "<target ip>: ip address of the target you wish to fool\n"
        << "<fake domain ip>: ip that you want the target to think the domain is at\n"
        << "<full domain name>: internet address you wish to spoof\n\n"
        << "Example: " << argv[0] << " eth0 "<< "10.0.2.33 " << "10.0.2.5 " << "www.google.com" << std::endl;
}

// TODO: improve args processing
int ProcessArgs(int argc, char** argv, char* interfaceName, uint32_t& ipVersion, uint32_t& queueNum, char* targetIP, char* fakeDomainIP, char* domain)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }

    if(argc != 7)
        return APPLICATION_ERROR;

    if(PacketCraft::GetStrLen(argv[1]) > IFNAMSIZ)
        return APPLICATION_ERROR;

    PacketCraft::CopyStr(interfaceName, IFNAMSIZ, argv[1]);

    if(PacketCraft::CompareStr(argv[2], "4") == TRUE)
        ipVersion = AF_INET;
    else if(PacketCraft::CompareStr(argv[2], "6") == TRUE)
        ipVersion = AF_INET6;
    else
        return APPLICATION_ERROR;

    queueNum = atoi(argv[3]);

    if(PacketCraft::GetStrLen(argv[4]) > INET6_ADDRSTRLEN)
        return APPLICATION_ERROR;
    else
        PacketCraft::CopyStr(targetIP, INET6_ADDRSTRLEN, argv[4]);

    if(PacketCraft::GetStrLen(argv[5]) > INET6_ADDRSTRLEN)
        return APPLICATION_ERROR;
    else
        PacketCraft::CopyStr(fakeDomainIP, INET6_ADDRSTRLEN, argv[5]);


    if(PacketCraft::GetStrLen(argv[6]) > FQDN_MAX_STR_LEN)
        return APPLICATION_ERROR;
    else
        PacketCraft::CopyStr(domain, FQDN_MAX_STR_LEN, argv[6]);

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    char domain[FQDN_MAX_STR_LEN]{};
    char targetIP[INET6_ADDRSTRLEN]{};
    char fakeDomainIP[INET6_ADDRSTRLEN]{};
    uint32_t ipVersion{};
    uint32_t queueNum{};

    if(ProcessArgs(argc, argv, interfaceName, ipVersion, queueNum, targetIP, fakeDomainIP, domain) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    } 

    PacketCraft::Packet packet;
    PacketCraft::PacketFilterQueue queue(&packet, queueNum, ipVersion == 4 ? AF_INET : AF_INET6, FilterPacket, EditPacket,
        PacketCraft::PC_ACCEPT, PacketCraft::PC_ACCEPT);

    if(queue.Run() == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::PacketFilterQueue::Run() error!");
        return APPLICATION_ERROR;
    }


    std::cout << std::flush;
    return NO_ERROR;    

    return NO_ERROR;    
}