#ifndef DNS_SPOOFER_H
#define DNS_SPOOFER_H

#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

namespace CHaks
{
    class DNSSpoofer
    {
        public:
        DNSSpoofer();
        ~DNSSpoofer();

        int Spoof(int socketFd, const char* interfaceName, char* targetIP, char* domain, char* fakeDomainIP);
        int CreateFakeDNSResponse(int socketFd, const char* interfaceName, PacketCraft::Packet& dnsRequestPacket,
            PacketCraft::Packet& dnsResponsePacket, char* fakeDomainIP, const PacketCraft::DNSQuestion& question);

        private:
        PacketCraft::DNSParser dnsParser;
    };
}

#endif