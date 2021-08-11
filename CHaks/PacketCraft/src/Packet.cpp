#include "Packet.h"
#include "Utils.h"
#include "NetworkUtils.h"
#include "ARP.h"

// general C++ stuff
#include <iostream>
#include <fstream>

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
    uint8_t* packet = (uint8_t*)malloc(IP_MAXPACKET);
    sockaddr fromInfo{};
    socklen_t fromInfoLen{sizeof(fromInfo)};

    pollfd pollFds[1]{};
    pollFds[0].fd = socketFd;
    pollFds[0].events = POLLIN;

    int bytesReceived{};

    int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), waitTimeoutMS);
    if(nEvents == -1)
    {
        free(packet);
        // LOG_ERROR(APPLICATION_ERROR, "poll() error!");
        return APPLICATION_ERROR;
    }
    else if(nEvents == 0)
    {
        free(packet);
        // LOG_ERROR(APPLICATION_ERROR, "poll() timed out.");
        return APPLICATION_ERROR;
    }
    else if(pollFds[0].revents & POLLIN)
    {
        bytesReceived = recvfrom(socketFd, packet, IP_MAXPACKET, flags, &fromInfo, &fromInfoLen);
        if(bytesReceived == -1)
        {
            free(packet);
            // LOG_ERROR(APPLICATION_ERROR, "recvfrom() error!");
            return APPLICATION_ERROR;
        }
        else if(bytesReceived == 0)
        {
            free(packet);
            // LOG_ERROR(APPLICATION_ERROR, "0 bytes received error!");
            return APPLICATION_ERROR;
        }
        else
        {
            ResetPacketBuffer();
            if(ProcessReceivedPacket(packet, 0) == APPLICATION_ERROR)
            {
                free(packet);
                // LOG_ERROR(APPLICATION_ERROR, "ProcessReceivedPacket() error!");
                return APPLICATION_ERROR;
            }
            else
            {
                free(packet);
                return NO_ERROR;
            }
        }
    }

    free(packet);
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

/*
int PacketCraft::Packet::Print(uint32_t layerSize, unsigned short protocol, uint32_t layerToPrintIndex)
{
    switch(protocol)
    {
        case PC_PROTO_ETH:
        {
            EthHeader* ethHeader = (EthHeader*)GetLayerStart(layerToPrintIndex);
            protocol = ntohs(ethHeader->ether_type);
            PrintEthernetLayer(ethHeader);
            ++layerToPrintIndex;
            break;
        }
        case ETH_P_ARP:
        {
            ARPHeader* arpHeader = (ARPHeader*)GetLayerStart(layerToPrintIndex);
            PrintARPLayer(arpHeader);
            return NO_ERROR;
        }
        case ETH_P_IP:
        {
            IPv4Header* ipHeader = (IPv4Header*)GetLayerStart(layerToPrintIndex);
            protocol = ipHeader->ip_p;

            // this is the next layer size
            layerSize = ntohs(ipHeader->ip_len) - (ipHeader->ip_hl * 32 / 8);

            PrintIPv4Layer(ipHeader);
            ++layerToPrintIndex;
            break;
        }
        case ETH_P_IPV6: // TODO: TEST!!!
        {
            IPv6Header* ipv6Header = (IPv6Header*)GetLayerStart(layerToPrintIndex);
            protocol = ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

            if(protocol == IPPROTO_ICMPV6)
                layerSize = ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen);

            PrintIPv6Layer(ipv6Header);
            ++layerToPrintIndex;
            break;
        }
        case IPPROTO_ICMP:
        {
            ICMPv4Header* icmpvHeader = (ICMPv4Header*)GetLayerStart(layerToPrintIndex);
            PrintICMPv4Layer(icmpvHeader, layerSize - sizeof(ICMPv4Header));
            return NO_ERROR;
        }
        case IPPROTO_ICMPV6:
        {
            ICMPv6Header* icmpv6Header = (ICMPv6Header*)GetLayerStart(layerToPrintIndex);
            PrintICMPv6Layer(icmpv6Header, layerSize - sizeof(ICMPv6Header));
            return NO_ERROR;
        }
        case IPPROTO_TCP: // TODO: TEST!!!
        {
            TCPHeader* tcpHeader = (TCPHeader*)GetLayerStart(layerToPrintIndex);
            if(tcpHeader->doff > 5)
            {
                PrintTCPLayer(tcpHeader, layerSize - sizeof(TCPHeader) - (uint32_t)*tcpHeader->optionsAndData + 1);
            }
            else
            {
                PrintTCPLayer(tcpHeader, layerSize - sizeof(TCPHeader));
            }
            return NO_ERROR;
        }
        default:
        {
            LOG_ERROR(APPLICATION_ERROR, "unsupported packet layer type received!");
            return APPLICATION_ERROR;
        }
    }

    return Print(layerSize, protocol, layerToPrintIndex);
}
*/

int PacketCraft::Packet::Print(bool32 printToFile, const char* fullFilePath) const
{
    std::ofstream file;
    uint32_t bufferSize = 5000;
    char* buffer = (char*)malloc(bufferSize);

    if(printToFile == TRUE)
    {
        file.open(fullFilePath, std::ofstream::out | std::ofstream::app);
    }

    uint32_t layerSize = 0; // next layer size, used to calculate data/options size of payloads
    for(unsigned int i = 0; i < nLayers; ++i)
    {
        uint32_t layerProtocol = GetLayerType(i);
        switch(layerProtocol)
        {
            case PC_ETHER_II:
            {
                EthHeader* ethHeader = (EthHeader*)GetLayerStart(i);
                PacketCraft::ConvertEthLayerToString(buffer, bufferSize, ethHeader);

                if(printToFile == TRUE)
                    file.write(buffer, PacketCraft::GetStrLen(buffer));
                else
                    std::cout << buffer << std::endl;

                break;
            }
            case PC_ARP:
            {
                ARPHeader* arpHeader = (ARPHeader*)GetLayerStart(i);
                PacketCraft::ConvertARPLayerToString(buffer, bufferSize, arpHeader);

                if(printToFile == TRUE)
                    file.write(buffer, PacketCraft::GetStrLen(buffer));
                else
                    std::cout << buffer << std::endl;

                break;
            }
            case PC_IPV4:
            {
                IPv4Header* ipv4Header = (IPv4Header*)GetLayerStart(i);
                PacketCraft::ConvertIPv4LayerToString(buffer, bufferSize, ipv4Header);

                layerSize = ntohs(ipv4Header->ip_len) - (ipv4Header->ip_hl * 32 / 8);

                if(printToFile == TRUE)
                    file.write(buffer, PacketCraft::GetStrLen(buffer));
                else
                    std::cout << buffer << std::endl;

                break;
            }
            case PC_IPV6:
            {
                IPv6Header* ipv6Header = (IPv6Header*)GetLayerStart(i);
                PacketCraft::ConvertIPv6LayerToString(buffer, bufferSize, ipv6Header);
                uint32_t nextProtocol = ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

                if(nextProtocol == IPPROTO_ICMPV6)
                    layerSize = ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen);

                if(printToFile == TRUE)
                    file.write(buffer, PacketCraft::GetStrLen(buffer));
                else
                    std::cout << buffer << std::endl;

                break;
            }
            case PC_ICMPV4:
            {
                ICMPv4Header* icmpv4Header = (ICMPv4Header*)GetLayerStart(i);
                PacketCraft::ConvertICMPv4LayerToString(buffer, bufferSize, icmpv4Header, layerSize - sizeof(ICMPv4Header));

                if(printToFile == TRUE)
                    file.write(buffer, PacketCraft::GetStrLen(buffer));
                else
                    std::cout << buffer << std::endl;

                break;
            }
            case PC_ICMPV6:
            {
                ICMPv6Header* icmpv6Header = (ICMPv6Header*)GetLayerStart(i);
                PacketCraft::ConvertICMPv6LayerToString(buffer, bufferSize, icmpv6Header, layerSize - sizeof(ICMPv6Header));

                if(printToFile == TRUE)
                    file.write(buffer, PacketCraft::GetStrLen(buffer));
                else
                    std::cout << buffer << std::endl;

                break;
            }
            case PC_TCP:
            {
                TCPHeader* tcpHeader = (TCPHeader*)GetLayerStart(i);

                if(tcpHeader->doff > 5)
                    PacketCraft::ConvertTCPLayerToString(buffer, bufferSize, tcpHeader, layerSize - sizeof(TCPHeader) - (uint32_t)*tcpHeader->optionsAndData + 1);
                else
                    PacketCraft::ConvertTCPLayerToString(buffer, bufferSize, tcpHeader, layerSize - sizeof(TCPHeader));
             
                if(printToFile == TRUE)
                    file.write(buffer, PacketCraft::GetStrLen(buffer));
                else
                    std::cout << buffer << std::endl;

                break;
            }
            default:
            {
                if(file.is_open())
                    file.close();

                free(buffer);
                LOG_ERROR(APPLICATION_ERROR, "unknown protocol detected!");
                return APPLICATION_ERROR;
            }

            memset(buffer, '\0', bufferSize);
        }
    }

    free(buffer);

    if(file.is_open())
        file.close();

    return NO_ERROR;
}

// TODO: extensive testing! This needs to be bulletproof!!!
int PacketCraft::Packet::ProcessReceivedPacket(uint8_t* packet, uint32_t layerSize, unsigned short protocol)
{
    switch(protocol)
    {
        case PC_PROTO_ETH:
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
        case ETH_P_IPV6: // TODO: TEST!!!
        {
            IPv6Header* ipv6Header = (IPv6Header*)packet;
            AddLayer(PC_IPV6, sizeof(IPv6Header));
            memcpy(GetLayerStart(nLayers - 1), packet, sizeof(IPv6Header));
            protocol = ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

            if(protocol == IPPROTO_ICMPV6 || protocol == IPPROTO_TCP)
                layerSize = ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen);

            packet += sizeof(IPv6Header);
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
        case IPPROTO_ICMPV6: // TODO: TEST!!!
        {
            AddLayer(PC_ICMPV6, layerSize);
            memcpy(GetLayerStart(nLayers - 1), packet, layerSize);

            if(layerSize > sizeof(ICMPv6Header))
            {
                // checks if there is a data field present. TODO: do we need to do anything?
            }
            return NO_ERROR;
        }
        case IPPROTO_TCP:
        {
            AddLayer(PC_TCP, layerSize);
            memcpy(GetLayerStart(nLayers - 1), packet, layerSize);

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