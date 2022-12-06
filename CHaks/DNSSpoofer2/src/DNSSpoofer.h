#ifndef DNS_SPOOFER_H
#define DNS_SPOOFER_H

#include "../../../../PacketCraft/PacketCraft/src/include/PCInclude.h"

extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
}

namespace CHaks
{
    struct NetFilterCallbackData
    {
        char domainName[FQDN_MAX_STR_LEN]{};                // provided by the user in program args
        char targetHostIPStr[INET6_ADDRSTRLEN]{};           // provided by the user in program args
        char newDomainIP[INET6_ADDRSTRLEN]{};               // provided by the user in program args
        char serverIPStr[INET6_ADDRSTRLEN]{};               // received in the netfilter callback
        char interfaceName[IFNAMSIZ]{};                     // provided by the user in program args
        uint32_t ipVersion{};
        mnl_socket *nl;
    };

    class DNSSpoofer
    {
        public:
        DNSSpoofer();
        ~DNSSpoofer();

        int Init(const char* domainName, const char* targetHostIP, const char* newDomainIP, const char* interfaceName, uint32_t ipVersion);
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