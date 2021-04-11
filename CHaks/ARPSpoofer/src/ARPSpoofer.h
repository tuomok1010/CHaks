#ifndef ARPSPOOFER_H
#define ARPSPOOFER_H

#define ARP_SPOOF_FREQUENCY_MS 2'000

namespace ARPSpoof
{
    class ARPSpoofer
    {
        public:
        ARPSpoofer();
        ~ARPSpoofer();

        int Spoof(int socketFd, const char* interfaceName, const char* srcMAC, const char* dstMAC, const char* srcIP, const char* targetIP);
        int SpoofLoop(int socketFd, const char* interfaceName, const char* srcMAC, const char* dstMAC, const char* srcIP, const char* targetIP);

        private:
        float timeElapsed;

    };
}
#endif