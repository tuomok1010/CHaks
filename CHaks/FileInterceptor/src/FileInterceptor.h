#ifndef PC_FILE_INTERCEPTOR_H
#define PC_FILE_INTERCEPTOR_H

#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

namespace CHaks
{
    class FileInterceptor
    {
        public:
        FileInterceptor();
        ~FileInterceptor();

        int Run(int socketFd, char* interfaceName, uint32_t ipVersion, char* targetIP, char* downloadLink);
        int FilterPackets(int socketFd, uint32_t ipVersion, char* targetIP, char* downloadLink, PacketCraft::Packet& packet);

        private:
    };
}

#endif