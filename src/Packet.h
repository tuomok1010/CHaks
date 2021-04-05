#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/ether.h>

#define IPV4_ALEN 4
#define IPV6_ALEN 16

#define PC_NONE         0x000000
#define PC_ETHER_II     0x000001
#define PC_ARP_REPLY    0x000002
#define PC_ARP_REQUEST  0x000003

#define PC_MAX_LAYERS   100

struct __attribute__((__packed__)) ARPHeader
{
    arphdr arpHdr;

    unsigned char ar_sha[ETH_ALEN];
    unsigned char ar_sip[IPV4_ALEN];
    unsigned char ar_tha[ETH_ALEN];
    unsigned char ar_tip[IPV4_ALEN];
};

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

        void AddLayer(const uint32_t layerType, const size_t layerSize);
        int Send(const int socket, const int flags, const sockaddr* dst, const size_t dstSize) const;

        void* GetLayerStart(const uint32_t layerIndex) const;
        void* GetLayerEnd(const uint32_t layerIndex) const;
        uint32_t GetLayerType(const uint32_t layerIndex) const;

        inline void* GetData() const { return data; }
        inline void* Start() const { return start; }
        inline void* End() const { return end; }

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