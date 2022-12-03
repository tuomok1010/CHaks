#ifndef DNS_SPOOFER_H
#define DNS_SPOOFER_H

#include "../../../../PacketCraft/PacketCraft/src/include/PCInclude.h"

// IMPORTANT: we are relying on the fact that our custom response reaches the target before the response from the actual
// dns server. Fix maybe?

namespace CHaks
{
    class DNSSpoofer
    {
        public:
        DNSSpoofer();
        ~DNSSpoofer();

        int Spoof(int socketFd, const char* interfaceName, char* targetIP, char* domain, char* fakeDomainIP);
        int ProcessPackets(int socketFd, const char* interfaceName, char* targetIP, char* domain, char* fakeDomainIP);
        int CreateFakeDNSResponse(PacketCraft::Packet& dnsRequestPacket, PacketCraft::Packet& dnsResponsePacket, char* fakeDomainIP, 
            IPVersion ipVersion, const PacketCraft::DNSQuestion& question);

        private:
        int CreateEthHeader(EthHeader& dnsResponseEthHeader, const EthHeader& dnsRequestEthHeader);
        int CreateIPv4Header(IPv4Header& dnsResponseIPv4Header, const IPv4Header& dnsRequestHeader);
        int CreateUDPHeader(UDPHeader& dnsResponseUDPHeader, const UDPHeader& dnsRequestUDPHeader);
        int CreateDNSHeader(DNSHeader& dnsResponseDNSHeader, const DNSHeader& dnsRequestDNSHeader, const PacketCraft::DNSQuestion& question, 
            char* fakeDomainIP, IPVersion ipVersion);
        PacketCraft::DNSParser dnsParser;
    };
}

#endif