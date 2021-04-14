#ifndef ARPSPOOFER_H
#define ARPSPOOFER_H

#define ARP_SPOOF_FREQUENCY_MS 2'000

struct sockaddr_in;
struct ether_addr;

namespace ARPSpoof
{
    class ARPSpoofer
    {
        public:
        ARPSpoofer();
        ~ARPSpoofer();

        int Spoof(const int socketFd, const char* interfaceName, const char* srcMAC, const char* dstMAC, const char* srcIP, const char* targetIP);
        int SpoofLoop(const int socketFd, const char* interfaceName, const char* srcMAC, const char* dstMAC, const char* srcIP, const char* targetIP);
        int GetARPTableAddr(const int socketFd, const char* interfaceName, const sockaddr_in& ipAddr, ether_addr& macAddr);
        int GetARPTableAddr(const int socketFd, const char* interfaceName, const char* ipAddrStr, ether_addr& macAddr);

        private:
        float timeElapsed;


    };
}
#endif