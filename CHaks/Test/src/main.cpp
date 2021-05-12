#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

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

    int socketFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(socketFd == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    char myIP[INET_ADDRSTRLEN]{};
    if(PacketCraft::GetIPAddr(myIP, ifName, AF_INET) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "GetIPAddr() error!");
        return APPLICATION_ERROR;
    }

    char myMAC[ETH_ADDR_STR_LEN]{};
    if(PacketCraft::GetMACAddr(myMAC, ifName, socketFd) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "GetMACAddr() error!");
        return APPLICATION_ERROR;
    }

    const char* dstIP = "10.0.2.1";
    const char* dstMAC = "52:54:00:12:35:00";

    PacketCraft::IPv4PingPacket pingPacket;
    if(pingPacket.Create(myMAC, dstMAC, myIP, dstIP, PingType::ECHO_REQUEST) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::IPv4PingPacket::Create() error!");
        return APPLICATION_ERROR;
    }

    std::cout << "sending the following packet: \n";
    pingPacket.PrintPacketData();

    if(pingPacket.Send(socketFd, ifName) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::IPv4PingPacket::Send() error!");
        return APPLICATION_ERROR;
    }

    close(socketFd);

    return NO_ERROR;
}