#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"
#include "DNSSpoofer.h"

#include <iostream>

#include <cstring>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>

struct DNSQuestion
{
    char qName[FQDN_MAX_STR_LEN];
    uint16_t qType;
    uint16_t qClass;
};

// IMPORTANT: remember to free() rData
struct DNSAnswer
{
    char aName[FQDN_MAX_STR_LEN];
    uint16_t aType;
    uint16_t aClass;
    uint32_t timeToLive;
    uint16_t rLength;
    char* rData;
};

class DNSParsedData
{
    public:
    DNSParsedData(DNSHeader& dnsHeader)
    {
        nQuestions = ntohs(dnsHeader.qcount);
        nAnswers = ntohs(dnsHeader.ancount);
        questions = new DNSQuestion[nQuestions];
        answers = new DNSAnswer[nAnswers];
    }

    ~DNSParsedData()
    {
        for(unsigned int i = 0; i < nAnswers; ++i)
            free(answers[i].rData);
    }

    uint32_t nQuestions;
    uint32_t nAnswers;
    DNSQuestion* questions;
    DNSAnswer* answers;
};

void ParseDNSQueries(DNSQuestion qArray[], DNSAnswer aArray[], DNSHeader& dnsHeader)
{
    uint8_t* querySection = dnsHeader.querySection;

    // parse questions
    for(unsigned int i = 0; i < htons(dnsHeader.qcount); ++i)
    {
        char* qNamePtr = qArray[i].qName;
        uint32_t nameLength = 0;
        while(true) // fills the qName buffer with a domain name
        {
            uint32_t labelLength = (uint32_t)*querySection; // first byte is the length of the first label
            ++querySection; // increment pointer to the start of the qname.
            memcpy(qNamePtr, querySection, labelLength); // copy label into the qName buffer
            querySection += labelLength; // will now point to the next label
            qNamePtr += labelLength;

            // append a '.' after each label
            *qNamePtr = '.';
            ++qNamePtr;

            nameLength += labelLength;

            // if length of next label is 0, we have reached the end of the qname string. We increment the pointer to point to the QTYPE value.
            if((uint32_t)*querySection == 0)
            {
                --qNamePtr; // move pointer back because we want the last '.' character to be replaced with a '\0'
                ++querySection;
                break;
            }
        }
        *qNamePtr = '\0';
        qArray[i].qType = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        qArray[i].qClass = ntohs(*(uint16_t*)querySection);
        querySection += 2; // ptr now points to the answers section
    }

    // parse answers
    for(unsigned int i = 0; i < htons(dnsHeader.ancount); ++i)
    {
        char* aNamePtr = aArray[i].aName;
        uint32_t nameLength = 0;
        while(true) // fills the qName buffer with a domain name
        {
            uint32_t labelLength = (uint32_t)*querySection; // first byte is the length of the first label
            ++querySection; // increment pointer to the start of the qname.
            memcpy(aNamePtr, querySection, labelLength); // copy label into the qName buffer
            querySection += labelLength; // will now point to the next label
            aNamePtr += labelLength;

            // append a '.' after each label
            *aNamePtr = '.';
            ++aNamePtr;

            nameLength += labelLength;

            // if length of next label is 0, we have reached the end of the qname string. We increment the pointer to point to the QTYPE value.
            if((uint32_t)*querySection == 0)
            {
                --aNamePtr; // move pointer back because we want the last '.' character to be replaced with a '\0'
                ++querySection;
                break;
            }
        }
        *aNamePtr = '\0';
        aArray[i].aType = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        aArray[i].aClass = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        aArray[i].timeToLive = ntohl(*(uint32_t*)querySection);
        querySection += 4;
        aArray[i].rLength = ntohs(*(uint16_t*)querySection);
        querySection += 2;

        aArray[i].rData = (char*)malloc(aArray[i].rLength + 1);
        memcpy(aArray[i].rData , querySection, aArray[i].rLength);
        memset(aArray[i].rData + aArray[i].rLength, '\0', 1);
        querySection += aArray[i].rLength;
    }
}

void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <target ip> <fake domain ip> <domain>\n\n"
        << "<interface name>: the interface you wish to use.\n"
        << "<target ip>: ip address of the target you wish to fool\n"
        << "<fake domain ip>: ip that you want the target to think the domain is at\n"
        << "<full domain name>: internet address you wish to spoof\n\n"
        << "Example: " << argv[0] << " eth0 "<< "10.0.2.33 " << "10.0.2.5 " << "https://www.google.com/" << std::endl;
}

// TODO: improve args processing
int ProcessArgs(int argc, char** argv, char* interfaceName, char* targetIP, char* fakeDomainIP, char* domain)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }

    if(argc != 5)
        return APPLICATION_ERROR;

    if(PacketCraft::GetStrLen(argv[1]) > IFNAMSIZ)
        return APPLICATION_ERROR;

    PacketCraft::CopyStr(interfaceName, IFNAMSIZ, argv[1]);

    if(PacketCraft::GetStrLen(argv[2]) > INET6_ADDRSTRLEN)
        return APPLICATION_ERROR;
    else
        PacketCraft::CopyStr(targetIP, INET6_ADDRSTRLEN, argv[2]);

    if(PacketCraft::GetStrLen(argv[3]) > INET6_ADDRSTRLEN)
        return APPLICATION_ERROR;
    else
        PacketCraft::CopyStr(fakeDomainIP, INET6_ADDRSTRLEN, argv[3]);


    if(PacketCraft::GetStrLen(argv[4]) > FQDN_MAX_STR_LEN)
        return APPLICATION_ERROR;
    else
        PacketCraft::CopyStr(domain, FQDN_MAX_STR_LEN, argv[4]);

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    char domain[FQDN_MAX_STR_LEN]{};
    char targetIP[INET6_ADDRSTRLEN]{};
    char fakeDomainIP[INET6_ADDRSTRLEN]{};

    if(ProcessArgs(argc, argv, interfaceName, targetIP, fakeDomainIP, domain) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    } 

    int socketFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(socketFd == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    while(true)
    {
        PacketCraft::Packet packet;
        if(packet.Receive(socketFd, 0) == APPLICATION_ERROR)
            continue;

        DNSHeader* dnsHeader = (DNSHeader*)packet.FindLayerByType(PC_DNS);
        if(dnsHeader != nullptr)
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
                    std::cout << "Matching IPv4 found in DNS packet\n";
                    packet.Print();
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



    close(socketFd);
    return NO_ERROR;    
}