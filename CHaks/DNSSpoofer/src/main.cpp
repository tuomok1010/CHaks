#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"
#include "DNSSpoofer.h"

#include <iostream>

#include <cstring>
#include <unistd.h>
#include <net/if.h>

void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <ip version> <target ip> <domain>\n\n"
        << "<interface name>: the interface you wish to use.\n"
        << "<ip version>: your ip version, must be 4 or 6\n"
        << "<target ip>: ip address of the target you wish to fool\n"
        << "<full domain>: internet address you wish to spoof\n\n"
        << "Example: " << argv[0] << " eth0 " << "4 " << "10.0.2.33 " << "https://www.google.com/" << std::endl;
}

// TODO: improve args processing
int ProcessArgs(int argc, char** argv, char* interfaceName, IPVersion& ipVersion, char* targetIP, char* domain)
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


    if(PacketCraft::CompareStr(argv[2], "4") == TRUE)
        ipVersion = IPVersion::IPV4;
    else if(PacketCraft::CompareStr(argv[2], "6") == TRUE)
        ipVersion = IPVersion::IPV6;
    else
        return APPLICATION_ERROR;


    if(PacketCraft::GetStrLen(argv[3]) > INET6_ADDRSTRLEN)
        return APPLICATION_ERROR;
    else
        PacketCraft::CopyStr(targetIP, INET6_ADDRSTRLEN, argv[3]);


    if(PacketCraft::GetStrLen(argv[4]) > FQDN_MAX_STR_LEN)
        return APPLICATION_ERROR;
    else
        PacketCraft::CopyStr(domain, FQDN_MAX_STR_LEN, argv[4]);

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    IPVersion ipVersion{IPVersion::NONE};
    char domain[FQDN_MAX_STR_LEN]{};
    char targetIP[INET6_ADDRSTRLEN]{};

    if(ProcessArgs(argc, argv, interfaceName, ipVersion, targetIP, domain) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    } 

    uint16_t socketProto = ipVersion == IPVersion::IPV4 ? ETH_P_IP : ETH_P_IPV6;
    int socketFd = socket(PF_PACKET, SOCK_RAW, htons(socketProto));
    if(socketFd == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    char myIP[INET6_ADDRSTRLEN]{};
    if(PacketCraft::GetIPAddr(myIP, interfaceName, ipVersion == IPVersion::IPV4 ? AF_INET : AF_INET6) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::GetIPAddr() error!");
        return APPLICATION_ERROR;
    }


    close(socketFd);
    return NO_ERROR;
}