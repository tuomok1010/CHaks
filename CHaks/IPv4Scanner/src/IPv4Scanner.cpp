#include "IPv4Scanner.h"

#include <iostream>
#include <iomanip>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <cstring>

CHaks::IPv4Scanner::IPv4Scanner()
{

}

CHaks::IPv4Scanner::~IPv4Scanner()
{
    
}

int CHaks::IPv4Scanner::CreateARPRequest(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, 
    PacketCraft::Packet& packet)
{
    packet.ResetPacketBuffer();

    packet.AddLayer(PC_ETHER_II, ETH_HLEN);
    EthHeader* ethHeader = (EthHeader*)packet.GetLayerStart(0);
    memcpy(ethHeader->ether_shost, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(ethHeader->ether_dhost, dstMAC.ether_addr_octet, ETH_ALEN);
    ethHeader->ether_type = htons(ETH_P_ARP);

    packet.AddLayer(PC_ARP, sizeof(ARPHeader));
    ARPHeader* arpHeader = (ARPHeader*)packet.GetLayerStart(1);
    arpHeader->ar_hrd = htons(ARPHRD_ETHER);
    arpHeader->ar_pro = htons(ETH_P_IP);
    arpHeader->ar_hln = ETH_ALEN;
    arpHeader->ar_pln = IPV4_ALEN;
    arpHeader->ar_op = htons(ARPOP_REQUEST);
    memcpy(arpHeader->ar_sha, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_sip, &srcIP.sin_addr.s_addr, IPV4_ALEN);
    memcpy(arpHeader->ar_tha, dstMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_tip, &dstIP.sin_addr.s_addr, IPV4_ALEN);

    return NO_ERROR;
}

int CHaks::IPv4Scanner::CreateARPRequest(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr,
    PacketCraft::Packet& packet)
{
    ether_addr srcMAC{};
    ether_addr dstMAC{};
    sockaddr_in srcIP{};
    sockaddr_in dstIP{};

    if(ether_aton_r(srcMACStr, &srcMAC) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_aton_r(dstMACStr, &dstMAC) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    if(inet_pton(AF_INET, srcIPStr, &srcIP.sin_addr) <= 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    if(inet_pton(AF_INET, dstIPStr, &dstIP.sin_addr) <= 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    return CreateARPRequest(srcMAC, dstMAC, srcIP, dstIP, packet);
}

int CHaks::IPv4Scanner::SendARPPackets(const char* interfaceName, const int socketFd, const sockaddr_in& srcIP, const ether_addr& srcMAC,
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

        PacketCraft::Packet packet;
        if(CreateARPRequest(srcMAC, targetMAC, srcIP, targetIP, packet) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "CreateARPRequest() error!");
            return APPLICATION_ERROR;
        }

        if(packet.Send(socketFd, interfaceName, 0) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::Send() error!");
            return APPLICATION_ERROR;
        }
    }

    return NO_ERROR;
}

int CHaks::IPv4Scanner::ReceiveARPPackets(const char* interfaceName, const int socketFd, bool32& running)
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

int CHaks::IPv4Scanner::ProcessReceivedPacket(const char* interfaceName, const int socketFd, bool32 printHeader)
{
    PacketCraft::Packet packet;
    if(packet.Receive(socketFd, 0) == NO_ERROR)
    {
        sockaddr_in ipAddr{};
        ipAddr.sin_family = AF_INET;
        ARPHeader* arpHeader = (ARPHeader*)packet.FindLayerByType(PC_ARP);
        if(arpHeader == nullptr)
            return NO_ERROR;
        memcpy(&ipAddr.sin_addr.s_addr, arpHeader->ar_sip, IPV4_ALEN);

        ether_addr macAddr{};
        EthHeader* ethHeader = (EthHeader*)packet.FindLayerByType(PC_ETHER_II);
        if(ethHeader == nullptr)
            return NO_ERROR;
        memcpy(macAddr.ether_addr_octet, ethHeader->ether_shost, ETH_ALEN);

        // only print the address if it doesn't already exist in the arp table. NOTE: we cleared the ARP table in SendARPPackets() to
        // prevent printing duplicates
        if(PacketCraft::GetARPTableMACAddr(socketFd, interfaceName, ipAddr, macAddr) == APPLICATION_ERROR)
        {
            if(PrintResult(macAddr, ipAddr, printHeader) == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "PrintResult() error!");
                return APPLICATION_ERROR;
            }

            if(PacketCraft::AddAddrToARPTable(socketFd, interfaceName, ipAddr, *(ether_addr*)arpHeader->ar_sha) == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "Failed to add MAC address into the ARP table\n");
                return APPLICATION_ERROR;
            }
        }
    }

    return NO_ERROR;
}

int CHaks::IPv4Scanner::PrintResult(const ether_addr& macAddr, const sockaddr_in& ipAddr, bool32 printHeader)
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