#ifndef PC_FILE_INTERCEPTOR_H
#define PC_FILE_INTERCEPTOR_H

#include "/home/kali/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
}

namespace CHaks
{
    class FileInterceptor
    {
        public:
        #define CMD_LEN 1024

        FileInterceptor();
        ~FileInterceptor();

        int Init(const uint32_t ipVersion);

        int Run(const int socketFd, const char* interfaceName, const char* targetIP, const char* downloadLink, 
            const char* newDownloadLink);

        int Run2(const char* targetIP, const char* downloadLink, const char* newDownloadLink, 
            int (*netfilterCallbackFunc)(nfq_q_handle*, nfgenmsg*, nfq_data*, void*));

        int FilterRequest(const int socketFd, const char* targetIP, const char* downloadLink, PacketCraft::Packet& httpRequestPacket);

        int FilterResponse(const int socketFd, const char* targetIP, PacketCraft::Packet& httpResponsePacket);

        int ModifyResponse(PacketCraft::Packet& httpResponse, const char* newDownloadLink) const;

        int CreateResponse(const PacketCraft::Packet& originalResponse, PacketCraft::Packet& newResponse, const char* newDownloadLink) const;

        private:
            // we can filter the correct response using this number. If the sequence number of the response matches with
            // the ack number of the request, we know that it is the correct response and we want to edit it.
            uint32_t requestAckNum;

            bool32 requestFiltered;
            uint32_t ipVersion;

            EthHeader requestEthHeader;

            const char* tableName{"filter"};
            const char* chainName{"post_routing_1"}; // rough filter which filters for tcp traffic only
            int queueNum;
            nfq_handle* handler;
            nfq_q_handle* queue;
    };
}

#endif