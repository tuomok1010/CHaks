#include "FileInterceptor.h"

#include <iostream>

#include <net/if.h>
#include <unistd.h>
#include <cstring>

void PrintHelp(char** argv)
{

}

// TODO: improve args processing
int ProcessArgs(int argc, char** argv, char* interfaceName, uint32_t& ipVersion)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }

    if(argc != 3)
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

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    uint32_t ipVersion{};

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