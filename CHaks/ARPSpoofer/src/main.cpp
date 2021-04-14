#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "ARPSpoofer.h"

void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <source IP> <destination IP>"
        << std::endl;
}

// TODO: verify the given args format, and PrintHelp() if they are invalid.
int ProcessArgs(int argc, char** argv, char* ifName, char* srcIP, char* dstIP)
{
    if(argc != 4)
    {
        LOG_ERROR(APPLICATION_ERROR, "invalid args error!");
        return APPLICATION_ERROR;
    }
    else if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
    }

    PacketCraft::CopyStr(ifName, PacketCraft::GetStrLen(argv[1]), argv[1]);
    PacketCraft::CopyStr(srcIP, PacketCraft::GetStrLen(argv[2]), argv[2]);
    PacketCraft::CopyStr(dstIP, PacketCraft::GetStrLen(argv[3]), argv[3]);

    return NO_ERROR;
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
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }

    if(PacketCraft::GetIPAddr(originalSrcIP, interfaceName) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::GetIPAddr() error!");
        return APPLICATION_ERROR;
    }

    int socketFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(socketFd < 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    ARPSpoof::ARPSpoofer arpSpoofer;
    ether_addr testMAC;
    arpSpoofer.GetARPTableAddr(socketFd, "eth0", "10.0.2.1", testMAC);
    PacketCraft::PrintMACAddr(testMAC, "GetARPTableAddr() test result: ", "\n");


    close(socketFd);
    return 0;
}