#ifndef ARPSPOOFER_H
#define ARPSPOOFER_H

#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

#define ARP_SPOOF_FREQUENCY_MS  2'000
#define ARP_REQ_TIMEOUT_MS      5'000

namespace ARPSpoof
{
    class ARPSpoofer
    {
        public:
        ARPSpoofer();
        ~ARPSpoofer();

        int GetTargetMACAddr(const int socketFd, const char* interfaceName, const char* srcIPStr, const char* srcMACStr, 
            const char* targetIPStr, char* targetMACStr);

        int Spoof(const int socketFd, const char* interfaceName, const PacketCraft::ARPPacket& arpPacket);
        int SpoofLoop(const int socketFd, const char* interfaceName, const char* srcMAC, const char* dstMAC, const char* srcIP, const char* dstIP);

        int RestoreTarget();
    };
}
#endif