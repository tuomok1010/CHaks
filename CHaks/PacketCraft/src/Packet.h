#ifndef PC_PACKET_H
#define PC_PACKET_H

#include <stdint.h>
#include <sys/types.h>

#include "PCTypes.h"

/*
    TODO: IMPORTANT!!:
    When adding a new layer, we are freeing the old memory, allocating a new block and assigning the old data pointer to it. However, 
    all the start/end pointers of the previous layers in layerInfos[] will still be pointing to the old memory addresses. This is also 
    the cause of the bug in ARP class where the ethHeader* points to garbage values after adding the arp layer into the packet. 

    Perhaps fix this by making a single memory allocation for a packet buffer either here in the Packet constructor, OR take a pointer
    as a constructor parameter and do the allocation in the application that uses this lib. The packet buffer should be large enough 
    to hold any packet, maybe IP_MAXPACKET size. 

*/

namespace PacketCraft
{
    struct LayerInfo
    {
        uint32_t type;
        size_t sizeInBytes;

        uint8_t* start;
        uint8_t* end;
    };

    class Packet
    {
        public:
        Packet();
        Packet(void* packetBuffer);
        ~Packet();

        // Check PCTypes.h for valid layerTypes
        int AddLayer(const uint32_t layerType, const size_t layerSize);
        int Send(const int socket, const int flags, const sockaddr* dst, const size_t dstSize) const;
        int Receive(const int socketFd, const int flags, int waitTimeoutMS = -1);
        void ResetPacketBuffer();

        // if printToFile is true, prints the packet into a txt file in fullFilePath, otherwise prints it in console
        int Print(bool32 printToFile = FALSE, const char* fullFilePath = "") const;

        void* GetLayerStart(const uint32_t layerIndex) const;
        void* GetLayerEnd(const uint32_t layerIndex) const;
        uint32_t GetLayerType(const uint32_t layerIndex) const;
        uint32_t GetLayerSize(const uint32_t layerIndex) const;

        inline void* GetData() const { return data; }
        inline void* Start() const { return start; }
        inline void* End() const { return end; }
        inline int GetSizeInBytes() const { return sizeInBytes; }
        inline uint32_t GetNLayers() const { return nLayers; }

        protected:
        virtual int ProcessReceivedPacket(uint8_t* packet, uint32_t layerSize = 0, unsigned short nextHeader = PC_PROTO_ETH);
        virtual void FreePacket();

        /////////////////

        private:
        void* data;
        uint8_t* start;
        uint8_t* end;

        LayerInfo layerInfos[PC_MAX_LAYERS];

        int sizeInBytes;
        uint32_t nLayers;

        bool32 outsideBufferSupplied;
    };
}

#endif