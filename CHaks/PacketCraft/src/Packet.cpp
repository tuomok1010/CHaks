#include "Packet.h"
#include "Utils.h"

// general C++ stuff
#include <iostream>

#include <cstdlib>
#include <cstring>

#include <netinet/ether.h>

PacketCraft::Packet::Packet():
    data(nullptr),
    start(nullptr),
    end(nullptr),
    sizeInBytes(0),
    nLayers(0)
{
    for(int i = 0; i < PC_MAX_LAYERS; ++i)
    {
        layerInfos[i].type = PC_NONE;
        layerInfos[i].sizeInBytes = 0;
        layerInfos[i].start = nullptr;
        layerInfos[i].end = nullptr;
    }
}

PacketCraft::Packet::~Packet()
{
    FreePacket();
}

void PacketCraft::Packet::AddLayer(const uint32_t layerType, const size_t layerSize)
{
    size_t newDataSize = layerSize + sizeInBytes;
    void* newData = malloc(newDataSize);
    memcpy(newData, data, sizeInBytes);

    std::cout 
        << "Adding layer of type "  << layerType 
        << " with size "            << layerSize
        << ". Old size is "         << sizeInBytes
        << ". New size is "         << newDataSize 
        << std::endl;

    if(data)
    {           
        free(data);
    }
    
    data = malloc(newDataSize);
    memcpy(data, newData, newDataSize);
    free(newData);

    end = (uint8_t*)data + newDataSize;
    start = (uint8_t*)data;

    layerInfos[nLayers].start = (uint8_t*)end - layerSize;
    layerInfos[nLayers].end = (uint8_t*) end;
    layerInfos[nLayers].sizeInBytes = layerSize;
    layerInfos[nLayers].type = layerType;

    sizeInBytes += layerSize;
    ++nLayers;
}

int PacketCraft::Packet::Send(const int socket, const int flags, const sockaddr* dst, const size_t dstSize) const
{
    int bytesSent{};
    bytesSent = sendto(socket, data, sizeInBytes, flags, dst, dstSize);
    if(bytesSent != sizeInBytes)
    {
        LOG_ERROR(APPLICATION_ERROR, "sendto() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

void PacketCraft::Packet::FreePacket()
{
    if(data)
    {
        free(data);
        data = nullptr;

        for(int i = 0; i < PC_MAX_LAYERS; ++i)
        {
            layerInfos[i].type = PC_NONE;
            layerInfos[i].sizeInBytes = 0;
            layerInfos[i].start = nullptr;
            layerInfos[i].end = nullptr;
        }
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