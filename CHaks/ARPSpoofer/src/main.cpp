#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"
#include <netinet/in.h>
#include <iostream>

#include "ARPSpoofer.h"

// TODO: verify the given args format, and PrintHelp() if they are invalid.
int ProcessArgs(int argc, char** argv, char* ifName, const char* srcIP, const char* dstIP)
{
    if(argc != 4)
    {
        LOG_ERROR(APPLICATION, "invalid args error!");
        return APPLICATION_ERROR;
    }
    else if(argc == 2 && argv[1] == "?")
    {
        PrintHelp();
    }

    PacketCraft::CopyStr(ifName, PacketCraft::GetStrLen(argv[1]), argv[1]);
    PacketCraft::CopyStr(srcIP, PacketCraft::GetStrLen(argv[2]), argv[2]);
    PacketCraft::CopyStr(dstIP, PacketCraft::GetStrLen(argv[3]), argv[3]);

    return NO_ERROR;
}

void PrintHelp()
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <source IP> <destination IP>"
        << std::endl;
}

int main(int argc, char** argv)
{
    // used when restoring target arp table
    sockaddr_in originalSrcIP{};

    char interfaceName[IFNAMSIZ]{};
    char srcIPStr[INET_ADDRSTRLEN]{};
    char dstIPStr[INET_ADDRSTRLEN]{};

    if(ProcessArgs(argc, argv, interfaceName, srcIPStr, dstIPStr) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp();
        return APPLICATION_ERROR;
    }

    if(PacketCraft::GetIPAddr(originalSrcIP, interfaceName) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::GetIPAddr() error!");
        return APPLICATION_ERROR;
    }

    

    return 0;
}