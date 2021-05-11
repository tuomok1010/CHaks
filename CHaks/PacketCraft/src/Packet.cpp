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

// TODO: extensive testing! This needs to be bulletproof!!!
int PacketCraft::Packet::ProcessReceivedPacket(uint8_t* packet, unsigned short protocol)
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
        default:
        {
            ResetPacketBuffer();
            // LOG_ERROR(APPLICATION_ERROR, "unsupported packet layer type received! Packet data cleared.");
            return APPLICATION_ERROR;
        }
    }

    return ProcessReceivedPacket(packet, protocol);

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