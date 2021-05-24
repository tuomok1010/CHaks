#include "Packet.h"
#include "Utils.h"
#include "ARP.h"

// general C++ stuff
#include <iostream>

#include <cstdlib>
#include <cstring>
#include <poll.h>

#include <netinet/ether.h>
#include <netinet/ip.h>

PacketCraft::Packet::Packet():
    data(nullptr),
    start(nullptr),
    end(nullptr),
    sizeInBytes(0),
    nLayers(0),
    outsideBufferSupplied(FALSE)
{
    for(int i = 0; i < PC_MAX_LAYERS; ++i)
    {
        layerInfos[i].type = PC_NONE;
        layerInfos[i].sizeInBytes = 0;
        layerInfos[i].start = nullptr;
        layerInfos[i].end = nullptr;
    }

    data = malloc(IP_MAXPACKET);

    /*
    if(data == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "malloc() error!");
    }
    */

    start = (uint8_t*)data;
    end = (uint8_t*)data;
}

PacketCraft::Packet::Packet(void* packetBuffer):
    data(nullptr),
    start(nullptr),
    end(nullptr),
    sizeInBytes(0),
    nLayers(0),
    outsideBufferSupplied(TRUE)
{
    for(int i = 0; i < PC_MAX_LAYERS; ++i)
    {
        layerInfos[i].type = PC_NONE;
        layerInfos[i].sizeInBytes = 0;
        layerInfos[i].start = nullptr;
        layerInfos[i].end = nullptr;
    }

    data = packetBuffer;
    /*
    if(data == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "buffer supplied is null!");
    }
    */

    start = (uint8_t*)data;
    end = (uint8_t*)data;
}

PacketCraft::Packet::~Packet()
{
    if(outsideBufferSupplied == FALSE)
    {
        FreePacket();
    }
}

int PacketCraft::Packet::AddLayer(const uint32_t layerType, const size_t layerSize)
{
    size_t newDataSize = layerSize + sizeInBytes;
    
    start = (uint8_t*)data;
    end = (uint8_t*)data + newDataSize;

    layerInfos[nLayers].start = (uint8_t*)end - layerSize;
    layerInfos[nLayers].end = (uint8_t*) end;
    layerInfos[nLayers].sizeInBytes = layerSize;
    layerInfos[nLayers].type = layerType;

    sizeInBytes += layerSize;
    ++nLayers;

    return NO_ERROR;
}

int PacketCraft::Packet::Send(const int socket, const int flags, const sockaddr* dst, const size_t dstSize) const
{
    int bytesSent{};
    bytesSent = sendto(socket, data, sizeInBytes, flags, dst, dstSize);
    if(bytesSent != sizeInBytes)
    {
        // LOG_ERROR(APPLICATION_ERROR, "sendto() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}


int PacketCraft::Packet::Receive(const int socketFd, const int flags, int waitTimeoutMS)
{
    uint8_t packet[IP_MAXPACKET]{};
    sockaddr fromInfo{};
    socklen_t fromInfoLen{sizeof(fromInfo)};

    pollfd pollFds[1]{};
    pollFds[0].fd = socketFd;
    pollFds[0].events = POLLIN;

    int bytesReceived{};

    int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), waitTimeoutMS);
    if(nEvents == -1)
    {
        // LOG_ERROR(APPLICATION_ERROR, "poll() error!");
        return APPLICATION_ERROR;
    }
    else if(nEvents == 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "poll() timed out.");
        return APPLICATION_ERROR;
    }
    else if(pollFds[0].revents & POLLIN)
    {
        bytesReceived = recvfrom(socketFd, packet, IP_MAXPACKET, flags, &fromInfo, &fromInfoLen);
        if(bytesReceived == -1)
        {
            // LOG_ERROR(APPLICATION_ERROR, "recvfrom() error!");
            return APPLICATION_ERROR;
        }
        else if(bytesReceived == 0)
        {
            // LOG_ERROR(APPLICATION_ERROR, "0 bytes received error!");
            return APPLICATION_ERROR;
        }
        else
        {
            ResetPacketBuffer();
            if(ProcessReceivedPacket(packet, 0) == APPLICATION_ERROR)
            {
                // LOG_ERROR(APPLICATION_ERROR, "ProcessReceivedPacket() error!");
                return APPLICATION_ERROR;
            }
            else
            {
                return NO_ERROR;
            }
        }
    }

    // LOG_ERROR(APPLICATION_ERROR, "unknown error!");
    return APPLICATION_ERROR;
}

void PacketCraft::Packet::ResetPacketBuffer()
{
    if(data)
    {
        memset(data, 0, sizeInBytes);
    }

    start = (uint8_t*)data;
    end = (uint8_t*)data;
    sizeInBytes = 0;
    nLayers = 0;

    for(int i = 0; i < PC_MAX_LAYERS; ++i)
    {
        layerInfos[i].type = PC_NONE;
        layerInfos[i].sizeInBytes = 0;
        layerInfos[i].start = nullptr;
        layerInfos[i].end = nullptr;
    }
}

int PacketCraft::Packet::Print()
{

}

int PacketCraft::Packet::PrintEthernetLayer(EthHeader* ethHeader)
{
    char ethDstAddr[ETH_ADDR_STR_LEN]{};    /* destination eth addr	*/
    char ethSrcAddr[ETH_ADDR_STR_LEN]{};    /* source ether addr	*/

    if(ether_ntoa_r((ether_addr*)ethHeader->ether_dhost, ethDstAddr) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r((ether_addr*)ethHeader->ether_shost, ethSrcAddr) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    std::cout
    << "[ETHERNET]:\n"
    << "destination: "    << ethDstAddr << "\n"
    << "source: "         << ethSrcAddr << "\n"
    << "type: 0x"         << std::hex << ntohs(ethHeader->ether_type) << "(" << std::dec << ntohs(ethHeader->ether_type) << ")\n"
    << " = = = = = = = = = = = = = = = = = = = = " << std::endl;
}

int PacketCraft::Packet::PrintARPLayer(ARPHeader* arpHeader)
{
    char ar_sha[ETH_ADDR_STR_LEN]{};    /* Sender hardware address.  */
    char ar_sip[INET_ADDRSTRLEN]{};     /* Sender IP address.  */
    char ar_tha[ETH_ADDR_STR_LEN]{};    /* Target hardware address.  */
    char ar_tip[INET_ADDRSTRLEN]{};     /* Target IP address.  */

    if(inet_ntop(AF_INET, arpHeader->ar_sip, ar_sip, INET_ADDRSTRLEN) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    if(inet_ntop(AF_INET, arpHeader->ar_tip, ar_tip, INET_ADDRSTRLEN) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r((ether_addr*)arpHeader->ar_sha, ar_sha) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r((ether_addr*)arpHeader->ar_tha, ar_tha) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    std::cout
    << "[ARP]:\n"
    << "hardware type: "        << ntohs(arpHeader->ar_hrd) << "\n"
    << "protocol type: "        << ntohs(arpHeader->ar_pro) << "\n"
    << "hardware size: "        << (uint16_t)arpHeader->ar_hln << "\n"
    << "protocol size: "        << (uint16_t)arpHeader->ar_pln << "\n"
    << "op code: "              << ntohs(arpHeader->ar_op) << " (" << (ntohs(arpHeader->ar_op) == 1 ? "request" : "reply") << ")\n"
    << "sender MAC address: "   << ar_sha << "\n"
    << "sender IP address: "    << ar_sip << "\n"
    << "target MAC address: "   << ar_tha << "\n"
    << "target IP address: "    << ar_tip << "\n"
    << " = = = = = = = = = = = = = = = = = = = = " << std::endl;
}

int PacketCraft::Packet::PrintIPv4Layer(IPv4Header* ipv4Header)
{
    char srcIPStr[INET_ADDRSTRLEN]{};
    char dstIPStr[INET_ADDRSTRLEN]{};

    if(inet_ntop(AF_INET, &ipv4Header->ip_src, srcIPStr, INET_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    if(inet_ntop(AF_INET, &ipv4Header->ip_dst, dstIPStr, INET_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    // TODO: move VerifyIPv4Checksum() from IPv4PingPacket to network utils!
    const char* ipv4ChecksumVerified = VerifyIPv4Checksum(ipv4Header, ipv4Header->ip_hl) == TRUE ? "verified" : "unverified";
    bool32 flagDFSet = ((ntohs(ipv4Header->ip_off)) & (IP_DF)) != 0;
    bool32 flagMFSet = ((ntohs(ipv4Header->ip_off)) & (IP_MF)) != 0;

    // TODO: test
    bool32 hasIpv4Options = ipv4Header->ip_hl > 5 ? TRUE : FALSE;
    uint32_t ipv4OptionsSize = ipv4Header->ip_hl - 5;

    std::cout
        << "[IPv4]:\n"
        << "ip version: "     << ipv4Header->ip_v << "\n"
        << "header length: "  << ipv4Header->ip_hl << "\n"
        << "ToS: 0x"          << std::hex << (uint16_t)ipv4Header->ip_tos << std::dec << "\n"  // TODO: print DSCP and ECN separately
        << "total length: "   << ntohs(ipv4Header->ip_len) << "\n"
        << "identification: " << ntohs(ipv4Header->ip_id) << "\n"
        << "flags: 0x"        << std::hex << ntohs(ipv4Header->ip_off) << std::dec << "(" << ntohs(ipv4Header->ip_off) << ")\n"
        << "\t bit 1(DF): "   << flagDFSet << " bit 2(MF): " << flagMFSet << "\n"
        << "time to live: "   << (uint16_t)ipv4Header->ip_ttl << "\n"
        << "protocol: "       << (uint16_t)ipv4Header->ip_p << "\n"
        << "checksum: "       << ntohs(ipv4Header->ip_sum) << "(" << ipv4ChecksumVerified << ")" << "\n"
        << "source: "         << srcIPStr << " " << "destination: " << dstIPStr << "\n";

    if(hasIpv4Options == TRUE)
    {
        int newLineAt = 7;
        for(unsigned int i = 0; i < ipv4OptionsSize; ++i)
        {
            std::cout << std::hex << ipv4Header->options[i];
            if(i % newLineAt == 0)
                std::cout << "\n";
        }
        std::cout << std::dec << " = = = = = = = = = = = = = = = = = = = = " << std::endl;
    }
}

int PacketCraft::Packet::PrintICMPv4Layer(ICMPv4Header* icmpv4Header)
{

}

// TODO: extensive testing! This needs to be bulletproof!!!
int PacketCraft::Packet::ProcessReceivedPacket(uint8_t* packet, uint32_t layerSize, unsigned short protocol)
{
    switch(protocol)
    {
        case 0:
        {
            AddLayer(PC_ETHER_II, ETH_HLEN);
            memcpy(data, packet, ETH_HLEN);
            protocol = ntohs(((EthHeader*)packet)->ether_type);
            packet += ETH_HLEN;
            break;
        }
        case ETH_P_ARP:
        {
            AddLayer(PC_ARP, sizeof(ARPHeader));
            memcpy(GetLayerStart(nLayers - 1), packet, sizeof(ARPHeader));
            return NO_ERROR;
        }
        case ETH_P_IP:
        {
            IPv4Header* ipHeader = (IPv4Header*)packet;
            AddLayer(PC_IPV4, ipHeader->ip_hl * 32 / 8);
            memcpy(GetLayerStart(nLayers - 1), packet, ipHeader->ip_hl * 32 / 8);
            protocol = ipHeader->ip_p;

            // this is the next layer size
            layerSize = ntohs(ipHeader->ip_len) - (ipHeader->ip_hl * 32 / 8);

            if(ipHeader->ip_hl > 5)
            {   
                // checks if there is an options field present. TODO: do we need to do anything?
            }

            packet += (uint32_t)ipHeader->ip_hl * 32 / 8;
            break;
        }
        case IPPROTO_ICMP:
        {
            AddLayer(PC_ICMPV4, layerSize);
            memcpy(GetLayerStart(nLayers - 1), packet, layerSize);

            if(layerSize > sizeof(ICMPv4Header))
            {
                // checks if there is a data field present. TODO: do we need to do anything?
            }

            return NO_ERROR;
        }
        default:
        {
            ResetPacketBuffer();
            LOG_ERROR(APPLICATION_ERROR, "unsupported packet layer type received! Packet data cleared.");
            return APPLICATION_ERROR;
        }
    }

    return ProcessReceivedPacket(packet, layerSize, protocol);

}

void PacketCraft::Packet::FreePacket()
{
    if(data)
    {
        free(data);
    }

    data = nullptr;
    start = nullptr;
    end = nullptr;
    sizeInBytes = 0;
    nLayers = 0;

    for(int i = 0; i < PC_MAX_LAYERS; ++i)
    {
        layerInfos[i].type = PC_NONE;
        layerInfos[i].sizeInBytes = 0;
        layerInfos[i].start = nullptr;
        layerInfos[i].end = nullptr;
    }
}

void* PacketCraft::Packet::GetLayerStart(const uint32_t layerIndex) const
{
    return layerInfos[layerIndex].start;
}

void* PacketCraft::Packet::GetLayerEnd(const uint32_t layerIndex) const 
{
    return layerInfos[layerIndex].end;
}

uint32_t PacketCraft::Packet::GetLayerType(const uint32_t layerIndex) const
{
    return layerInfos[layerIndex].type;
}