#include "CodeInjector.h"

#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <poll.h>
#include <cstring>

 static int nfq_send_verdict(int queue_num, uint32_t id, mnl_socket* nl, pkt_buff* pkBuff)
 {
    char buf[MNL_SOCKET_BUFFER_SIZE];
    nlmsghdr* nlh;
    nlattr* nest;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);

    if(pktb_mangled(pkBuff))
    {
        std::cout << "packet was mangled" << std::endl;
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pkBuff), pktb_len(pkBuff));
    }

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

    return NO_ERROR;
 }

static int queueCallback(const nlmsghdr *nlh, void *data)
{
    std::cout << "--------------------\n";
    nfqnl_msg_packet_hdr* ph{nullptr};
    nlattr* attr[NFQA_MAX + 1]{};
    nfgenmsg*nfg{nullptr};

    CHaks::NetFilterCallbackData callbackData = *(CHaks::NetFilterCallbackData*)data;

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
        LOG_ERROR(APPLICATION_ERROR, "mnl_attr_get_payload() NFQA_PACKET_HDR error");
        return MNL_CB_ERROR;
    }

    uint16_t plen{0};
    uint8_t* payload{nullptr};

    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    payload = (uint8_t*)mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
    if(payload == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "mnl_attr_get_payload() NFQA_PAYLOAD error");
        return MNL_CB_ERROR;
    }

    printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u\n", ntohl(ph->packet_id), ntohs(ph->hw_protocol), ph->hook, plen);

    uint32_t ipVersion{};
    if(ntohs(ph->hw_protocol) == ETH_P_IP)
        ipVersion = AF_INET;
    else if(ntohs(ph->hw_protocol) == ETH_P_IPV6)
        ipVersion = AF_INET6;

    pkt_buff* pkBuff = pktb_alloc(ipVersion, payload, plen, 4'096);
    if(pkBuff == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "pktb_alloc() error");
        return MNL_CB_ERROR;
    }

    iphdr* ipv4Header{nullptr};
    ip6_hdr* ipv6Header{nullptr};
    tcphdr* tcpHeader{nullptr};

    if(ipVersion == AF_INET)
    {
        ipv4Header = nfq_ip_get_hdr(pkBuff);
        if(ipv4Header == nullptr)
        {
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "nfq_ip_get_hdr() error");
            return MNL_CB_ERROR;
        }

        if(nfq_ip_set_transport_header(pkBuff, ipv4Header) < 0)
        {
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "nfq_ip_set_transport_header() error");
            return MNL_CB_ERROR;
        }

        if(ipv4Header->protocol == IPPROTO_TCP)
        {

        }
        else // no TCP layer in packet
        {
            std::cout << "no tcp header in packet\n";
            if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff) == APPLICATION_ERROR)
            {
                pktb_free(pkBuff);
                LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
                return MNL_CB_ERROR;
            }
            return MNL_CB_OK;
        }
    }
    else if(ipVersion == AF_INET6)
    {
        ipv6Header = nfq_ip6_get_hdr(pkBuff);
        if(ipv6Header == nullptr)
        {
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "nfq_ip6_get_hdr()");
            return MNL_CB_ERROR;
        }

        int res = nfq_ip6_set_transport_header(pkBuff, ipv6Header, IPPROTO_TCP);
        if(res == 1)
        {

        }
        else if(res < 0) // no TCP layer in packet
        {
            std::cout << "no tcp header found in packet\n";
            if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff) == APPLICATION_ERROR)
            {
                pktb_free(pkBuff);
                LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
                return MNL_CB_ERROR;
            }
            return MNL_CB_OK;
        }
    }

    tcpHeader = nfq_tcp_get_hdr(pkBuff);
    if(tcpHeader == nullptr)
    {
        pktb_free(pkBuff);
        LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_get_hdr");
        return MNL_CB_ERROR;
    }

    void *tcpPayload = nfq_tcp_get_payload(tcpHeader, pkBuff);
    if(tcpPayload == nullptr)
    {
        pktb_free(pkBuff);
        LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_get_payload() error");
        return MNL_CB_ERROR;
    }

    unsigned int tcpPayloadLen = nfq_tcp_get_payload_len(tcpHeader, pkBuff);

    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
        return MNL_CB_ERROR;
    }

    return MNL_CB_OK;
}

CHaks::CodeInjector::CodeInjector() :
    ipVersion(0),
    queueNum(0),
    handler(nullptr),
    queue(nullptr)
{

}

CHaks::CodeInjector::~CodeInjector()
{
    if(queue != nullptr)
        nfq_destroy_queue(queue);

    if(handler != nullptr)
        nfq_close(handler);
}

int CHaks::CodeInjector::Init(const uint32_t ipVersion, const char* interfaceName, const char* targetIP, int queueNum)
{
    this->ipVersion = ipVersion; // TODO: obsolete because ip is now passed in callbackData. remove when ready
    this->queueNum = queueNum;

    callbackData.ipVersion = ipVersion;
    PacketCraft::CopyStr(callbackData.targetIPStr, INET6_ADDRSTRLEN, targetIP);
    PacketCraft::CopyStr(callbackData.interfaceName, IFNAMSIZ, interfaceName);

    return NO_ERROR;
}

int CHaks::CodeInjector::Run()
{
    char* buffer{nullptr};
    nlmsghdr* nlh{nullptr};
    /* largest possible packet payload, plus netlink data overhead: */
    size_t bufferSize = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
    int res;

    callbackData.nl = mnl_socket_open(NETLINK_NETFILTER);
    if(callbackData.nl == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_open() error");
        return APPLICATION_ERROR;
    }

    if(mnl_socket_bind(callbackData.nl, 0, MNL_SOCKET_AUTOPID) < 0) 
    {
        mnl_socket_close(callbackData.nl);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_bind() error");
        return APPLICATION_ERROR;
    }

    portId = mnl_socket_get_portid(callbackData.nl);

    buffer = (char*)malloc(bufferSize);
    if(!buffer) 
    {
        mnl_socket_close(callbackData.nl);
        LOG_ERROR(APPLICATION_ERROR, "malloc() error");
        return APPLICATION_ERROR;
    }

    nlh = nfq_nlmsg_put(buffer, NFQNL_MSG_CONFIG, queueNum);
    if(nlh == nullptr)
    {
        mnl_socket_close(callbackData.nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "nfq_nlmsg_put() error");
        return APPLICATION_ERROR;
    }

    nfq_nlmsg_cfg_put_cmd(nlh, ipVersion, NFQNL_CFG_CMD_BIND);

    if(mnl_socket_sendto(callbackData.nl, nlh, nlh->nlmsg_len) < 0) 
    {
        mnl_socket_close(callbackData.nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_sendto() error");
        return APPLICATION_ERROR;
    }
 
    nlh = nfq_nlmsg_put(buffer, NFQNL_MSG_CONFIG, queueNum);
    if(nlh == nullptr)
    {
        mnl_socket_close(callbackData.nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "nfq_nlmsg_put() error");
        return APPLICATION_ERROR;
    }

    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, IP_MAXPACKET);
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if(mnl_socket_sendto(callbackData.nl, nlh, nlh->nlmsg_len) < 0) 
    {
        mnl_socket_close(callbackData.nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_sendto() error");
        return APPLICATION_ERROR;
    }

    /* ENOBUFS is signalled to userspace when packets were lost
    * on kernel side.  In most cases, userspace isn't interested
    * in this information, so turn it off.
    */
    res = 1;
    mnl_socket_setsockopt(callbackData.nl, NETLINK_NO_ENOBUFS, &res, sizeof(int));

    pollfd pollFds[2]{-1, -1};
    pollFds[0].fd = 0;
    pollFds[0].events = POLLIN;
    pollFds[1].fd = mnl_socket_get_fd(callbackData.nl);
    pollFds[1].events = POLLIN;

    while(true)
    {
        int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), -1);
        if(nEvents == -1)
        {
            mnl_socket_close(callbackData.nl);
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "poll() error");
            return APPLICATION_ERROR;
        }
        else if(pollFds[1].revents & POLLIN) // we have a packet in the queue
        {
            res = mnl_socket_recvfrom(callbackData.nl, buffer, bufferSize);
            if (res == -1) 
            {
                mnl_socket_close(callbackData.nl);
                free(buffer);
                LOG_ERROR(APPLICATION_ERROR, "mnl_socket_recvfrom() error");
                return APPLICATION_ERROR;
            }

            res = mnl_cb_run(buffer, res, 0, portId, queueCallback, &callbackData);
            if (res < 0)
            {
                mnl_socket_close(callbackData.nl);
                free(buffer);
                LOG_ERROR(APPLICATION_ERROR, "mnl_cb_run() error");
                return APPLICATION_ERROR;
            }
        }
        else if(pollFds[0].revents & POLLIN) // user hit a key and wants to quit program
        {
            break;
        }
        else
        {
            mnl_socket_close(callbackData.nl);
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "unknown poll() error!");
            return APPLICATION_ERROR;
        }

    }

    mnl_socket_close(callbackData.nl);
    free(buffer);
    return NO_ERROR;
}