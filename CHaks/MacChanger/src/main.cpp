#include "../../../PacketCraft/src/include/PCInclude.h"

#include <netinet/in.h>
#include <unistd.h>
#include <net/if.h>

#include <iostream>

void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <mac address>\n\n"
        << "<interface name>: the interface you wish to change the MAC address of.\n"
        << "<mac address>: new mac address\n"
        << std::endl;
}

int ProcessArgs(int argc, char** argv, char* interfaceName, char* newMAC)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }
    else if(argc != 3)
    {
        return APPLICATION_ERROR;
    }

    PacketCraft::CopyStr(interfaceName, PacketCraft::GetStrLen(argv[1]), argv[1]);
    PacketCraft::CopyStr(newMAC, PacketCraft::GetStrLen(argv[2]), argv[2]);

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char newMAC[ETH_ADDR_STR_LEN]{};
    char interfaceName[IFNAMSIZ]{};

    if(ProcessArgs(argc, argv, interfaceName, newMAC) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }

    int socketFd = socket(PF_PACKET, SOCK_RAW, ETH_P_IP);
    if(socketFd == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    if(PacketCraft::SetMACAddr(socketFd, interfaceName, newMAC) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::SetMACAddr() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}