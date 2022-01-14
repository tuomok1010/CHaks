#include "FileInterceptor.h"

#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <poll.h>
#include <cstring>

 static int nfq_send_verdict(int queue_num, uint32_t id, mnl_socket* nl)
 {
        char buf[MNL_SOCKET_BUFFER_SIZE];
        nlmsghdr *nlh;
        nlattr *nest;

        nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
        nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

        /* example to set the connmark. First, start NFQA_CT section: */
        nest = mnl_attr_nest_start(nlh, NFQA_CT);

        /* then, add the connmark attribute: */
        mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
        /* more conntrack attributes, e.g. CTA_LABELS could be set here */

        /* end conntrack section */
        mnl_attr_nest_end(nlh, nest);

        if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) 
        {
            LOG_ERROR(APPLICATION_ERROR, "mnl_socket_sendto() error");
            return APPLICATION_ERROR;
        }
 }

 static int queueCallback(const nlmsghdr *nlh, void *data)
 {
    nfqnl_msg_packet_hdr* ph{nullptr};
    nlattr* attr[NFQA_MAX + 1]{};
    uint32_t id{0};
    uint32_t skbInfo{0};
    nfgenmsg*nfg{nullptr};
    uint16_t plen{0};

    mnl_socket* nl = (mnl_socket*)data;

    if(nfq_nlmsg_parse(nlh, attr) < 0) 
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_nlmsg_parse() error");
        return MNL_CB_ERROR;
    }

    nfg = (nfgenmsg*)mnl_nlmsg_get_payload(nlh);
    if(nfg == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "mnl_nlmsg_get_payload() error");
        return MNL_CB_ERROR;
    }

    if(attr[NFQA_PACKET_HDR] == NULL) 
    {
        LOG_ERROR(APPLICATION_ERROR, "metaheader not set");
        return MNL_CB_ERROR;
    }

    ph = (nfqnl_msg_packet_hdr*)mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
    if(ph == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "mnl_attr_get_payload() error");
        return MNL_CB_ERROR;
    }
    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);

    skbInfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    if(attr[NFQA_CAP_LEN]) 
    {
        uint32_t origLen = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
        if (origLen != plen)
                printf("truncated ");
    }

    if(skbInfo & NFQA_SKB_GSO)
        printf("GSO ");

    id = ntohl(ph->packet_id);
    printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u", id, ntohs(ph->hw_protocol), ph->hook, plen);

        /*
    * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
    * The application should behave as if the checksums are correct.
    *
    * If these packets are later forwarded/sent out, the checksums will
    * be corrected by kernel/hardware.
    */
    if (skbInfo & NFQA_SKB_CSUMNOTREADY)
            printf(", checksum not ready");
    puts(")");

    if(nfq_send_verdict(ntohs(nfg->res_id), id, nl) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
        return MNL_CB_ERROR;
    }

    return MNL_CB_OK;
 }

CHaks::FileInterceptor::FileInterceptor() :
    requestAckNum(0),
    requestFiltered(FALSE),
    ipVersion(0),
    queueNum(0),
    handler(nullptr),
    queue(nullptr)
{

}

CHaks::FileInterceptor::~FileInterceptor()
{
    char cmd[CMD_LEN]{};

    snprintf(cmd, CMD_LEN, "nft flush table %s %s",  ipVersion == AF_INET ? "ip" : "ip6", tableName);
    system(cmd);

    memset(cmd, 0, CMD_LEN);

    snprintf(cmd, CMD_LEN, "nft delete table %s %s",  ipVersion == AF_INET ? "ip" : "ip6", tableName);
    system(cmd);

    if(queue != nullptr)
        nfq_destroy_queue(queue);

    if(handler != nullptr)
        nfq_close(handler);
}

int CHaks::FileInterceptor::Init(const uint32_t ipVersion, const char* interfaceName, const char* targetIP, const char* downloadLink, const char* newDownloadLink,
    int queueNum)
{
    this->ipVersion = ipVersion; // TODO: obsolete because ip is now passed in callbackData. remove when ready
    this->queueNum = queueNum;

    callbackData.ipVersion = ipVersion;
    PacketCraft::CopyStr(callbackData.targetIPStr, INET6_ADDRSTRLEN, targetIP);
    PacketCraft::CopyStr(callbackData.downloadLink, DOWNLOAD_LINK_STR_SIZE, downloadLink);
    PacketCraft::CopyStr(callbackData.newDownloadLink, DOWNLOAD_LINK_STR_SIZE, newDownloadLink);
    PacketCraft::CopyStr(callbackData.interfaceName, IFNAMSIZ, interfaceName);

    char cmd[CMD_LEN]{};

    snprintf(cmd, CMD_LEN, "nft add table %s %s", ipVersion == AF_INET ? "ip" : "ip6", tableName);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() error! failed to create nft table");
        return APPLICATION_ERROR;
    }
    memset(cmd, 0, CMD_LEN);

    // Add chain 1(postrouting) and rules to it
    snprintf(cmd, CMD_LEN, "nft \'add chain %s %s %s { type filter hook input priority 0 ; }\'", ipVersion == AF_INET ? "ip" : "ip6", tableName, chain1Name);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() error! failed to add chain1");
        return APPLICATION_ERROR;
    }
    memset(cmd, 0, CMD_LEN);

    snprintf(cmd, CMD_LEN, "nft add rule %s %s %s meta l4proto tcp", ipVersion == AF_INET ? "ip" : "ip6", tableName, chain1Name);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() error! failed to add meta rules in chain");
        return APPLICATION_ERROR;
    }
    memset(cmd, 0, CMD_LEN);

    snprintf(cmd, CMD_LEN, "nft add rule %s %s %s queue num %d", ipVersion == AF_INET ? "ip" : "ip6", tableName, chain1Name, queueNum);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() error! failed to add queue rule in chain");
        return APPLICATION_ERROR;
    }
    //////////////////////////////////////

    // Add chain 2(prerouting) and rules to it
    snprintf(cmd, CMD_LEN, "nft \'add chain %s %s %s { type filter hook output priority 0 ; }\'", ipVersion == AF_INET ? "ip" : "ip6", tableName, chain2Name);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() error! failed to add chain1");
        return APPLICATION_ERROR;
    }
    memset(cmd, 0, CMD_LEN);

    snprintf(cmd, CMD_LEN, "nft add rule %s %s %s meta l4proto tcp", ipVersion == AF_INET ? "ip" : "ip6", tableName, chain2Name);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() error! failed to add meta rules in chain");
        return APPLICATION_ERROR;
    }
    memset(cmd, 0, CMD_LEN);

    snprintf(cmd, CMD_LEN, "nft add rule %s %s %s queue num %d", ipVersion == AF_INET ? "ip" : "ip6", tableName, chain2Name, queueNum);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() error! failed to add queue rule in chain");
        return APPLICATION_ERROR;
    }
    //////////////////////////////////////

    std::cout << "chains created:\n";
    system("nft list ruleset");

    return NO_ERROR;
}

int CHaks::FileInterceptor::RunTest()
{
    char* buffer{nullptr};
    nlmsghdr* nlh{nullptr};
    /* largest possible packet payload, plus netlink data overhead: */
    size_t bufferSize = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
    int res;

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if(nl == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_open() error");
        return APPLICATION_ERROR;
    }

    if(mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) 
    {
        mnl_socket_close(nl);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_bind() error");
        return APPLICATION_ERROR;
    }

    portId = mnl_socket_get_portid(nl);

    buffer = (char*)malloc(bufferSize);
    if(!buffer) 
    {
        mnl_socket_close(nl);
        LOG_ERROR(APPLICATION_ERROR, "malloc() error");
        return APPLICATION_ERROR;
    }

    nlh = nfq_nlmsg_put(buffer, NFQNL_MSG_CONFIG, queueNum);
    if(nlh == nullptr)
    {
        mnl_socket_close(nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "nfq_nlmsg_put() error");
        return APPLICATION_ERROR;
    }

    nfq_nlmsg_cfg_put_cmd(nlh, ipVersion, NFQNL_CFG_CMD_BIND);

    if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) 
    {
        mnl_socket_close(nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_sendto() error");
        return APPLICATION_ERROR;
    }
 
    nlh = nfq_nlmsg_put(buffer, NFQNL_MSG_CONFIG, queueNum);
    if(nlh == nullptr)
    {
        mnl_socket_close(nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "nfq_nlmsg_put() error");
        return APPLICATION_ERROR;
    }

    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, IP_MAXPACKET);
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) 
    {
        mnl_socket_close(nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_sendto() error");
        return APPLICATION_ERROR;
    }

    /* ENOBUFS is signalled to userspace when packets were lost
    * on kernel side.  In most cases, userspace isn't interested
    * in this information, so turn it off.
    */
    res = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &res, sizeof(int));

    while(true) // TODO: use poll to monitor console input, test if mnl_socket works with poll()
    {
        res = mnl_socket_recvfrom(nl, buffer, bufferSize);
        if (res == -1) 
        {
            mnl_socket_close(nl);
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "mnl_socket_recvfrom() error");
            return APPLICATION_ERROR;
        }

        res = mnl_cb_run(buffer, res, 0, portId, queueCallback, nl);
        if (res < 0)
        {
            mnl_socket_close(nl);
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "mnl_cb_run() error");
            return APPLICATION_ERROR;
        }
    }

    mnl_socket_close(nl);
    free(buffer);
}

int CHaks::FileInterceptor::Run(int (*netfilterCallbackFunc)(nfq_q_handle*, nfgenmsg*, nfq_data*, void*))
{
    handler = nfq_open();
    if(handler == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_open() error");
        return APPLICATION_ERROR;
    }

    queue = nfq_create_queue(handler, queueNum, netfilterCallbackFunc, &callbackData);
    if(queue == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_create_queue() error");
        return APPLICATION_ERROR;
    }

    if(nfq_set_mode(queue, NFQNL_COPY_PACKET, IP_MAXPACKET) < 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_set_mode() error");
        return APPLICATION_ERROR;
    }

    int socketFd = nfq_fd(handler);
    char buffer[IP_MAXPACKET]{}; // TODO: can we use a PacketCraft::Packet here and pass it to the nfq_handle_packet?
    struct pollfd pollFds[2];

    pollFds[0].fd = 0;
    pollFds[0].events = POLLIN;
    pollFds[1].fd = socketFd;
    pollFds[1].events = POLLIN;

    std::cout << "running...press enter to stop" << std::endl;

    while(true)
    {
        int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), -1);
        if(nEvents == -1)
        {
            close(socketFd);
            LOG_ERROR(APPLICATION_ERROR, "poll() error");
            return APPLICATION_ERROR;
        }
        else if(pollFds[1].revents & POLLIN) // we have a packet in the queue
        {
            int len = read(pollFds[1].fd, buffer, IP_MAXPACKET);
            if(len < 0)
            {
                close(socketFd);
                LOG_ERROR(APPLICATION_ERROR, "read() error");
                return APPLICATION_ERROR;
            }

            nfq_handle_packet(handler, buffer, len);
        }
        else if(pollFds[0].revents & POLLIN) // user hit a key and wants to quit program
        {
            break;
        }
        else
        {
            close(socketFd);
            LOG_ERROR(APPLICATION_ERROR, "unknown poll() error!");
            return APPLICATION_ERROR;
        }
    }

    close(socketFd);
    std::cout << "quitting..." << std::endl;
    return NO_ERROR;
}