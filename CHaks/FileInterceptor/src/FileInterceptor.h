#ifndef PC_FILE_INTERCEPTOR_H
#define PC_FILE_INTERCEPTOR_H

#include "../../../PacketCraft/src/include/PCInclude.h"

namespace CHaks
{
    class FileInterceptor
    {
        public:
        FileInterceptor();
        ~FileInterceptor();

        int Run(const int socketFd, const char* interfaceName, const uint32_t ipVersion, const char* targetIP, const char* downloadLink, 
            const char* newDownloadLink);

        int FilterPackets(const int socketFd, const uint32_t ipVersion, const char* targetIP, const char* downloadLink, 
            const char* newDownloadLink, PacketCraft::Packet& packet);

        int CreateResponse(const PacketCraft::Packet& originalResponse, PacketCraft::Packet& newResponse, const char* newDownloadLink) const;

        private:
            // we can filter the correct response using this number. If the sequence number of the response matches with
            // the ack number of the request, we know that it is the correct response and we want to edit it.
            uint32_t requestAckNum;
    };
}

#endif