#ifndef PC_CODE_INJECTOR_H
#define PC_CODE_INJECTOR_H

// #include "../../../PacketCraft/src/include/PCInclude.h"
#include "/home/kali/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

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

#define PATH_MAX_SIZE  512

namespace CHaks
{
    struct NetFilterCallbackData
    {
        mnl_socket *nl;
        uint32_t ipVersion;             // provided by the user in program args
        const char* targetIPStr{};      // provided by the user in program args
        char* serverIPStr{};            // received in the netfilter callback
        const char* interfaceName{};    // provided by the user in program args
        const char* url{};              // provided by the user in program args
        const char* code{};             // read from a file in main()
        int codeLen{};
    };

    class CodeInjector
    {
        public:
        CodeInjector();
        ~CodeInjector();

        int Init(const uint32_t ipVersion, const char* interfaceName, const char* targetIP, int queueNum, const char* url,
            const char* injectCode, int injectCodeLen);
        int Run();


        private:
            NetFilterCallbackData callbackData;

            uint32_t queueNum;
            uint32_t portId;

            nfq_handle* handler;
            nfq_q_handle* queue;
    };
}

#endif