#include "../../../../PacketCraft/PacketCraft/src/include/PCInclude.h"

#include <iostream>
#include <cstring>
#include <arpa/inet.h>

bool32 FilterPacket(const PacketCraft::Packet& packet)
{
    std::cout << "in FilterPacket()" << std::endl;
    IPv4Header* ipv4Header = (IPv4Header*)packet.FindLayerByType(PC_IPV4);

    sockaddr_in ip;
    PacketCraft::GetIPAddr(ip, "enp0s3");

    sockaddr_in ipPacket;
    ipPacket.sin_addr.s_addr = ipv4Header->ip_src.s_addr;
    PacketCraft::PrintIPAddr(ip, "enp0s3 IP: ", ", ");
    PacketCraft::PrintIPAddr(ipPacket, "packet ip: ", "\n");

    if(ip.sin_addr.s_addr == ipv4Header->ip_src.s_addr)
        return TRUE;
    else
        return FALSE;
}

uint32_t EditPacket(PacketCraft::Packet& packet)
{
    std::cout << "in EditPacket()" << std::endl;
/*
    IPv4Header* ipv4Header = (IPv4Header*)packet.FindLayerByType(PC_IPV4);

    char newIPStr[INET6_ADDRSTRLEN]{"10.0.2.69"};
    sockaddr_in newIP;
    inet_pton(AF_INET, newIPStr, &newIP.sin_addr);

    char ip[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &ipv4Header->ip_src, ip, INET6_ADDRSTRLEN);
    std::cout << "original src IP: " << ip << std::endl;

    memcpy(&ipv4Header->ip_src, &newIP.sin_addr, IPV4_ALEN);
    inet_ntop(AF_INET, &ipv4Header->ip_src, ip, INET6_ADDRSTRLEN);

    std::cout << "new src IP: " << ip << std::endl;

    std::cout << "original checksum: " << ntohs(ipv4Header->ip_sum);
    packet.CalculateChecksums();
    std::cout << "new checksum: " << ntohs(ipv4Header->ip_sum) << std::endl;
*/

    packet.CalculateChecksums();
    return NO_ERROR;
}
  
int main(int argc, char** argv)
{
    int queueNum{1};
    int af{AF_INET};

    PacketCraft::Packet packet;
    PacketCraft::PacketFilterQueue packetQueue(packet, queueNum, af, FilterPacket, EditPacket, PacketCraft::PC_ACCEPT, PacketCraft::PC_ACCEPT);

    if(packetQueue.Init() == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::PacketFilterQueue::Init() error!");
        return APPLICATION_ERROR;
    }
    else
    {
        std::cout << "NO ERROR" << std::endl;
    }

    return NO_ERROR;
 } 