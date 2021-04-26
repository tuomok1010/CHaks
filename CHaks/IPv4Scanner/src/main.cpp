#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

#include <iostream>
#include <arpa/inet.h>

// TODO: make this more bulletproof
int ProcessArgs(int argc, char** argv, const char* ifName)
{
    if(argc != 2)
    {
        LOG_ERROR(APPLICATION_ERROR, "invalid args error!");
        return APPLICATION_ERROR;
    }

    if(PacketCraft::GetStrLen(argv[1]) > IFNAMSIZ)
    {
        LOG_ERROR(APPLICATION_ERROR, "invalid args error!");
        return APPLICATION_ERROR;
    }

    PacketCraft::CopyStr(ifName, PacketCraft::GetStrLen(ifName), argv[1]);

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char ifName[IFNAMSIZ]{};
    if(ProcessArgs(argc, argv) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        return APPLICATION_ERROR;
    }

    int socketFd = socket(AF_INET, SOCK_RAW, htons(ETH_P_ARP));
    if(socketFd == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_in networkAddr{};
    if(PacketCraft::GetNetworkAddr(networkAddr, ifName, socketFd) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "GetNetworkAddr() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_in broadcastAddr{};
    if(PacketCraft::GetBroadcastAddr(broadcastAddr, ifName, socketFd) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "GetBroadcastAddr() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_in myIP{};
    if(PacketCraft::GetIPAddr(myIP, ifName) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "GetIPAddr() error!");
        return APPLICATION_ERROR;
    }

    ether_addr myMAC{};
    if(PacketCraft::GetMACAddr(myMAC, ifName, socketFd) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "GetMACAddr() error!");
        return APPLICATION_ERROR;
    }

    bool32 running{TRUE};

    return NO_ERROR;
}