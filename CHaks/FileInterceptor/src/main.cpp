#include "FileInterceptor.h"

#include <iostream>

#include <net/if.h>
#include <unistd.h>
#include <cstring>

void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <ip version> <target ip> <download link>\n\n"
        << "<interface name>: the interface you wish to use.\n"
        << "<ip version>: ip version of the target, must be 4 or 6\n"
        << "<target ip>: target whose file you wish to intercept\n\n"
        << "Example: " << argv[0] << " eth0 "<< "4" << "10.0.2.4" << std::endl;
}

// TODO: improve args processing
int ProcessArgs(int argc, char** argv, char* interfaceName, uint32_t& ipVersion, char* targetIP)
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
        ipVersion = AF_INET;
    else if(PacketCraft::CompareStr(argv[2], "6") == TRUE)
        ipVersion = AF_INET6;
    else
        return APPLICATION_ERROR;

    PacketCraft::CopyStr(targetIP, INET6_ADDRSTRLEN, argv[3]);

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    uint32_t ipVersion{};
    char targetIP[INET6_ADDRSTRLEN]{};

    if(ProcessArgs(argc, argv, interfaceName, ipVersion) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    } 

    int socketFd = socket(PF_PACKET, SOCK_RAW, htons(ipVersion == AF_INET ? ETH_P_IP : ETH_P_IPV6));

    

    close(socketFd);
    return NO_ERROR;    
}