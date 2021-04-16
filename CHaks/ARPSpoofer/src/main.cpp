#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

#include <netinet/in.h>
#include <arpa/inet.h> 
#include <iostream>

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "ARPSpoofer.h"


void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <source IP> <destination IP> <enable port forward(true/false)>\n\n"
        << "<interface name>: the interface you wish to sent the packets from.\n"
        << "<source ip>: the ip you wish the destination device to think you are.\n"
        << "<destination ip>: the target device you wish to fool.\n"
        << "<enable port forward(true/false)>: setting this to true allows the program to auto-enable portforward with the command\n"
        << "\'echo 1 > /proc/sys/net/ipv4/ip_forward\'. False will do nothing, and you will have to enable it manually."
        << std::endl;
}

// TODO: verify the given args format, and PrintHelp() if they are invalid.
int ProcessArgs(int argc, char** argv, char* ifName, char* srcIP, char* dstIP, bool32& portForward)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }
    else if(argc != 5)
    {
        LOG_ERROR(APPLICATION_ERROR, "invalid args error!");
        return APPLICATION_ERROR;
    }

    PacketCraft::CopyStr(ifName, PacketCraft::GetStrLen(argv[1]), argv[1]);
    PacketCraft::CopyStr(srcIP, PacketCraft::GetStrLen(argv[2]), argv[2]);
    PacketCraft::CopyStr(dstIP, PacketCraft::GetStrLen(argv[3]), argv[3]);

    if(argv[4][0] == '1' || argv[4][0] == 't' || argv[4][0] == 'T' || argv[4][0] == 'y' || argv[4][0] == 'Y')
        portForward = TRUE;
    else
        portForward = FALSE;
    

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    sockaddr_in myIP{};
    ether_addr myMAC{};
    char myIPStr[INET_ADDRSTRLEN]{};
    char myMACStr[ETH_ADDR_STR_LEN]{};

    char interfaceName[IFNAMSIZ]{};
    char srcIPStr[INET_ADDRSTRLEN]{};
    char dstIPStr[INET_ADDRSTRLEN]{};
    bool32 portForward{FALSE};

    if(ProcessArgs(argc, argv, interfaceName, srcIPStr, dstIPStr, portForward) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }

    int socketFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(socketFd < 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    if(PacketCraft::GetIPAddr(myIP, interfaceName) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::GetIPAddr() error!");
        return APPLICATION_ERROR;
    }

    if(inet_ntop(AF_INET, &myIP.sin_addr, myIPStr, INET_ADDRSTRLEN) == nullptr)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    if(PacketCraft::GetMACAddr(myMAC, interfaceName, socketFd) == APPLICATION_ERROR)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::GetMACAddr() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r(&myMAC, myMACStr) == nullptr)
    {
        close(socketFd);
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    ether_addr dstMAC{};
    while (PacketCraft::GetARPTableMACAddr(socketFd, interfaceName, dstIPStr, dstMAC) == APPLICATION_ERROR)
    {
        PacketCraft::ARPPacket arpPacket;
        arpPacket.Create(myMACStr, "ff:ff:ff:ff:ff:ff", myIPStr, dstIPStr, ARPType::ARP_REQUEST);
        arpPacket.Send(socketFd, interfaceName);

        if(arpPacket.Receive(socketFd, 0, 5000) == NO_ERROR)
        {
            std::cout << "Received ARP packet:\n\n";
            arpPacket.PrintPacketData();

            char ip[INET_ADDRSTRLEN]{};
            char mac[ETH_ADDR_STR_LEN]{};

            if(inet_ntop(AF_INET, arpPacket.arpHeader->ar_sip, ip, INET_ADDRSTRLEN) == nullptr)
            {
                close(socketFd);
                LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
                return APPLICATION_ERROR;
            }

            ether_addr macAddr{};
            memcpy(macAddr.ether_addr_octet, arpPacket.arpHeader->ar_sha, ETH_ALEN);
            if(ether_ntoa_r(&macAddr, mac) == nullptr)
            {
                close(socketFd);
                LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
                return APPLICATION_ERROR;
            }

            PacketCraft::AddAddrToARPTable(socketFd, interfaceName, ip, mac);
        }
    }
    





    if(portForward == TRUE)
    {
        if(PacketCraft::EnablePortForwarding() == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "could not enable port forwarding\n");
            return APPLICATION_ERROR;
        }
    }


    ARPSpoof::ARPSpoofer arpSpoofer;


    if(portForward == TRUE)
        PacketCraft::DisablePortForwarding();

    close(socketFd);
    return 0;
}