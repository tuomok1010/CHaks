#include "../../../PacketCraft/src/include/PCInclude.h"
#include "IPv4Scanner.h"

#include <iostream>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>

void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name>\n\n"
        << "<interface name>: the interface you wish to sent the packets from.\n"
        << std::endl;
}

// TODO: make this more bulletproof
int ProcessArgs(int argc, char** argv, char* ifName)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }
    
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

    PacketCraft::CopyStr(ifName, IFNAMSIZ, argv[1]);

    return NO_ERROR;
}

// TODO: make an option to use a different protocol than ARP to do the scan. ARP spams a lot of broadcasts into the network.
int main(int argc, char** argv)
{
    char ifName[IFNAMSIZ]{};
    if(ProcessArgs(argc, argv, ifName) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }

    int socketFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(socketFd == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_in networkAddr{};
    if(PacketCraft::GetNetworkAddr(networkAddr, ifName, socketFd) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "GetNetworkAddr() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_in broadcastAddr{};
    if(PacketCraft::GetBroadcastAddr(broadcastAddr, ifName, socketFd) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "GetBroadcastAddr() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_in myIP{};
    if(PacketCraft::GetIPAddr(myIP, ifName) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "GetIPAddr() error!");
        return APPLICATION_ERROR;
    }

    ether_addr myMAC{};
    if(PacketCraft::GetMACAddr(myMAC, ifName, socketFd) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "GetMACAddr() error!");
        return APPLICATION_ERROR;
    }

    // NOTE: this was originally planned to be used in a multithreaded program. Right now it does nothing.
    bool32 running{TRUE};

    CHaks::IPv4Scanner scanner{};

    scanner.SendARPPackets(ifName, socketFd, myIP, myMAC, networkAddr, broadcastAddr, running);

    std::cout << "scanning...press enter to stop\n";

    scanner.ReceiveARPPackets(ifName, socketFd, running);

    std::cout << "exiting..." << std::endl;

    close(socketFd);

    return NO_ERROR;
}