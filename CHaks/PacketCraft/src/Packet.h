#ifndef PC_PACKET_H
#define PC_PACKET_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/ether.h>

#include "PCTypes.h"

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
        ~Packet();

        // NOTE: consider making these public, so that people could use this class to create packets more flexibly
        protected:
        void AddLayer(const uint32_t layerType, const size_t layerSize);
        int Send(const int socket, const int flags, const sockaddr* dst, const size_t dstSize) const;
        void FreePacket();

        void* GetLayerStart(const uint32_t layerIndex) const;
        void* GetLayerEnd(const uint32_t layerIndex) const;
        uint32_t GetLayerType(const uint32_t layerIndex) const;

        inline void* GetData() const { return data; }
        inline void* Start() const { return start; }
        inline void* End() const { return end; }
        inline int GetSizeInBytes() const { return sizeInBytes; }

        /////////////////

        private:
        void* data;
        uint8_t* start;
        uint8_t* end;

        LayerInfo layerInfos[PC_MAX_LAYERS];
        sockaddr dest;  // needed in sendto()

        int sizeInBytes;
        uint32_t nLayers;
    };
}

#endif