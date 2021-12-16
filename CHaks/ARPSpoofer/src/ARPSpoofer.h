#ifndef ARPSPOOFER_H
#define ARPSPOOFER_H

#include "../../../PacketCraft/src/include/PCInclude.h"

#define ARP_SPOOF_FREQUENCY_MS  2'000
#define ARP_REQ_TIMEOUT_MS      5'000

namespace CHaks
{
    class ARPSpoofer
    {
        public:
        ARPSpoofer();
        ~ARPSpoofer();

        int GetTargetMACAddr(const int socketFd, const char* interfaceName, const char* srcIPStr, const char* srcMACStr, 
            const char* targetIPStr, char* targetMACStr);

        int Spoof(const int socketFd, const char* interfaceName, const char* yourIP, const char* yourMAC, 
            const char* target1IPStr, const char* target1MACStr, const char* target2IPStr, const char* target2MACStr, const bool32 spoofBoth);
            
        int SpoofLoop(const int socketFd, const char* interfaceName, const char* yourIP, const char* yourMAC, 
            const char* target1IPStr, const char* target1MACStr, const char* target2IPStr, const char* target2MACStr, const bool32 spoofBoth);

        int RestoreTargets(const int socketFd, const char* interfaceName, const char* yourIP, const char* yourMAC, 
            const char* target1IPStr, const char* target1MACStr, const char* target2IPStr, const char* target2MACStr, const bool32 spoofBoth);
    };
}
#endif