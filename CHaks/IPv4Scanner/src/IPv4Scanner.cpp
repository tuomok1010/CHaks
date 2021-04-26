#include "IPv4Scanner.h"

#include <iostream>
#include <arpa/inet.h>
#include <poll.h>
#include <cstring>

IPv4Scan::IPv4Scanner::IPv4Scanner()
{

}

IPv4Scan::IPv4Scanner::~IPv4Scanner()
{
    
}

int IPv4Scan::IPv4Scanner::SendARPPackets(const char* interfaceName, const int socketFd, const sockaddr_in& srcIP, const ether_addr& srcMAC,
    const sockaddr_in& networkAddr, const sockaddr_in& broadcastAddr, bool32& running)
{
    uint32_t networkHostByteOrder = ntohl(networkAddr.sin_addr.s_addr);
    uint32_t broadcastHostByteOrder = ntohl(broadcastAddr.sin_addr.s_addr);

    for(uint32_t targetAddr = networkHostByteOrder + 1; targetAddr < broadcastHostByteOrder; ++targetAddr)
    {
        if(running == FALSE)
            break;

        sockaddr_in targetIP{};
        targetIP.sin_family = AF_INET;
        targetIP.sin_addr.s_addr = htonl(targetAddr);

        ether_addr targetMAC{};
        memset(targetMAC.ether_addr_octet, 0xff, ETH_ALEN);

        PacketCraft::ARPPacket arpPacket{};
        if(arpPacket.Create(srcMAC, targetMAC, srcIP, targetIP, ARPType::ARP_REQUEST) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "PacketCraft::ARPPacket::Create() error!");
            return APPLICATION_ERROR;
        }

        if(arpPacket.Send(socketFd, interfaceName) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "PacketCraft::ARPPacket::Send() error!");
            return APPLICATION_ERROR;
        }
    }

    return NO_ERROR;
}

int IPv4Scan::IPv4Scanner::ReceiveARPPackets(const char* interfaceName, const int socketFd, bool32& running)
{
    pollfd pollFds[2]{};
    pollFds[0].fd = 0;      
    pollFds[0].events = POLLIN;
    pollFds[1].fd = socketFd;
    pollFds[1].events = POLLIN;

    while(true)
    {
        int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), -1);
        if(nEvents == -1)
        {
            LOG_ERROR(APPLICATION_ERROR, "poll() error!");
            return APPLICATION_ERROR;
        }
        else if(pollFds[0].revents & POLLIN)
        {
            std::cout << "stopping...\n";
            running = FALSE;
            break;
        }
        else if(pollFds[1].revents & POLLIN)
        {
            if(ProcessReceivedPacket(interfaceName, socketFd) == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "ProcessReceivedPacket() error!");
                running = FALSE;
                return APPLICATION_ERROR;
            }
        }
    }

    return NO_ERROR;
}

int IPv4Scan::IPv4Scanner::ProcessReceivedPacket(const char* interfaceName, const int socketFd)
{
    PacketCraft::ARPPacket arpPacket{};
    if(arpPacket.Receive(socketFd, 0) == NO_ERROR)
    {
        sockaddr_in ipAddr{};
        ipAddr.sin_family = AF_INET;
        memcpy(&ipAddr.sin_addr.s_addr, arpPacket.arpHeader->ar_sip, IPV4_ALEN);

        if(PacketCraft::AddAddrToARPTable(socketFd, interfaceName, ipAddr, *(ether_addr*)arpPacket.arpHeader->ar_sha) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "Failed to add MAC address into the ARP table\n");
            return APPLICATION_ERROR;
        }
    }

    return NO_ERROR;
}

void IPv4Scan::IPv4Scanner::PrintARPTableContents(const char* interfaceName, const int socketFd)
{

}