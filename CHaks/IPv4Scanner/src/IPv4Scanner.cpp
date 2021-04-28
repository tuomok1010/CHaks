#include "IPv4Scanner.h"

#include <iostream>
#include <iomanip>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
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

        // clearing the address from the ARP cache, because we access the cache in ProcessReceivedPacket() to 
        // look if a address is already known to prevent printing the same ip/mac pair twice. 
        PacketCraft::RemoveAddrFromARPTable(socketFd, interfaceName, targetIP);

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

    // when printing the results, if this is true we also print the "header" on top of the ip-mac address pairs
    bool32 firstTimeThrough{TRUE};

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
            running = FALSE;
            break;
        }
        else if(pollFds[1].revents & POLLIN)
        {
            if(ProcessReceivedPacket(interfaceName, socketFd, firstTimeThrough) == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "ProcessReceivedPacket() error!");
                running = FALSE;
                return APPLICATION_ERROR;
            }

            firstTimeThrough = FALSE;
        }
    }

    return NO_ERROR;
}

int IPv4Scan::IPv4Scanner::ProcessReceivedPacket(const char* interfaceName, const int socketFd, bool32 printHeader)
{
    PacketCraft::ARPPacket arpPacket{};
    if(arpPacket.Receive(socketFd, 0) == NO_ERROR)
    {
        sockaddr_in ipAddr{};
        ipAddr.sin_family = AF_INET;
        memcpy(&ipAddr.sin_addr.s_addr, arpPacket.arpHeader->ar_sip, IPV4_ALEN);

        ether_addr macAddr{};
        memcpy(macAddr.ether_addr_octet, arpPacket.ethHeader->ether_shost, ETH_ALEN);

        // only print the address if it doesn't already exist in the arp table. NOTE: we cleared the ARP table in SendARPPackets() to
        // prevent printing duplicates
        if(PacketCraft::GetARPTableMACAddr(socketFd, interfaceName, ipAddr, macAddr) == APPLICATION_ERROR)
        {
            if(PrintResult(macAddr, ipAddr, printHeader) == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "PrintResult() error!");
                return APPLICATION_ERROR;
            }

            if(PacketCraft::AddAddrToARPTable(socketFd, interfaceName, ipAddr, *(ether_addr*)arpPacket.arpHeader->ar_sha) == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "Failed to add MAC address into the ARP table\n");
                return APPLICATION_ERROR;
            }
        }
    }

    return NO_ERROR;
}

int IPv4Scan::IPv4Scanner::PrintResult(const ether_addr& macAddr, const sockaddr_in& ipAddr, bool32 printHeader)
{
    char macStr[ETH_ADDR_STR_LEN]{};
    char ipStr[INET_ADDRSTRLEN]{};

    if(ether_ntoa_r(&macAddr, macStr) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    if(inet_ntop(AF_INET, &ipAddr.sin_addr, ipStr, INET_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    int outputWidth = ETH_ADDR_STR_LEN + 2;

    if(printHeader == TRUE)
        std::cout << std::setw(outputWidth) <<std::left << "MAC" << std::setw(outputWidth) << std::right << "IP\n";

    std::cout
        << std::left << std::setw(outputWidth) << macStr 
        << std::right << std::setw(outputWidth) << ipStr 
        << std::endl;

    return NO_ERROR;
}