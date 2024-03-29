#ifndef PC_FILE_INTERCEPTOR_H
#define PC_FILE_INTERCEPTOR_H

#include "../../../../PacketCraft/PacketCraft/src/include/PCInclude.h"

extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
}

#define DOWNLOAD_LINK_STR_SIZE  512

namespace CHaks
{
    struct NetFilterCallbackData
    {
        mnl_socket *nl;
        uint32_t ipVersion;                                 // provided by the user in program args
        char targetIPStr[INET6_ADDRSTRLEN]{};               // provided by the user in program args
        char serverIPStr[INET6_ADDRSTRLEN]{};               // received in the netfilter callback
        char downloadLink[DOWNLOAD_LINK_STR_SIZE]{};        // provided by the user in program args
        char newDownloadLink[DOWNLOAD_LINK_STR_SIZE]{};     // provided by the user in program args
        char interfaceName[IFNAMSIZ]{};                     // provided by the user in program args
    };

    class FileInterceptor
    {
        public:
        FileInterceptor();
        ~FileInterceptor();

        int Init(const uint32_t ipVersion, const char* interfaceName, const char* targetIP, const char* downloadLink, const char* newDownloadLink, int queueNum);
        int Run();


        private:
            uint32_t ipVersion;

            NetFilterCallbackData callbackData;

            uint32_t queueNum;
            uint32_t portId;

            nfq_handle* handler;
            nfq_q_handle* queue;
    };
}

#endif