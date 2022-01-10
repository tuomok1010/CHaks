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

int CHaks::FileInterceptor::Init(const uint32_t ipVersion, const char* targetIP, const char* downloadLink, const char* newDownloadLink)
{
    this->ipVersion = ipVersion; // TODO: obsolete because ip is now passed in callbackData. remove when ready

    callbackData.ipVersion = ipVersion;
    PacketCraft::CopyStr(callbackData.targetIPStr, INET6_ADDRSTRLEN, targetIP);
    PacketCraft::CopyStr(callbackData.downloadLink, DOWNLOAD_LINK_STR_SIZE, downloadLink);
    PacketCraft::CopyStr(callbackData.newDownloadLink, DOWNLOAD_LINK_STR_SIZE, newDownloadLink);

    char cmd[CMD_LEN]{};

    snprintf(cmd, CMD_LEN, "nft add table %s %s", ipVersion == AF_INET ? "ip" : "ip6", tableName);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() error! failed to create nft table");
        return APPLICATION_ERROR;
    }
    memset(cmd, 0, CMD_LEN);

    snprintf(cmd, CMD_LEN, "nft \'add chain %s %s %s { type filter hook postrouting priority 0 ; }\'", ipVersion == AF_INET ? "ip" : "ip6", tableName, chainName);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() error! failed to add chain1");
        return APPLICATION_ERROR;
    }
    memset(cmd, 0, CMD_LEN);

    snprintf(cmd, CMD_LEN, "nft add rule %s %s %s meta l4proto tcp", ipVersion == AF_INET ? "ip" : "ip6", tableName, chainName);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() error! failed to add meta rules in chain");
        return APPLICATION_ERROR;
    }
    memset(cmd, 0, CMD_LEN);

    snprintf(cmd, CMD_LEN, "nft add rule %s %s %s queue num %d", ipVersion == AF_INET ? "ip" : "ip6", tableName, chainName, queueNum);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system() error! failed to add queue rule in chain");
        return APPLICATION_ERROR;
    }

    std::cout << "chain created:\n";
    system("nft list ruleset");

    return NO_ERROR;
}

int CHaks::FileInterceptor::Run2(int (*netfilterCallbackFunc)(nfq_q_handle*, nfgenmsg*, nfq_data*, void*))
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

int CHaks::FileInterceptor::Run(const int socketFd, const char* interfaceName, const char* targetIP, 
    const char* downloadLink, const char* newDownloadLink)
{
    pollfd pollFds[2]{};

    // we want to monitor console input, entering something there stops the program
    pollFds[0].fd = 0;
    pollFds[0].events = POLLIN;

    pollFds[1].fd = socketFd;
    pollFds[1].events = POLLIN;

    PacketCraft::Packet httpRequestPacket;
    PacketCraft::Packet httpResponsePacket;

    std::cout << "waiting for packets... press enter to stop\n" << std::endl;

    while(true)
    {
        int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), -1);
        if(nEvents == -1)
        {
            LOG_ERROR(APPLICATION_ERROR, "poll() error!");
            return APPLICATION_ERROR;
        }
        else if(nEvents == 0)
        {
            LOG_ERROR(APPLICATION_ERROR, "poll() timeout!");
            return APPLICATION_ERROR;
        }
        else
        {
            if(pollFds[0].revents & POLLIN)
            {
                std::cout << "quitting...\n";
                return NO_ERROR;
            }
            else if(pollFds[1].revents & POLLIN)
            {   
                // NOTE: requestAckNum gets set in FilterRequest
                if(FilterRequest(socketFd, targetIP, downloadLink, httpRequestPacket) == NO_ERROR)
                {
                    std::cout << "request filtered:\n";
                    httpRequestPacket.Print();
                    requestFiltered = TRUE;

                    EthHeader* reqEthHeader = (EthHeader*)httpRequestPacket.GetLayerStart(0);
                    memcpy(requestEthHeader.ether_dhost, reqEthHeader->ether_dhost, ETH_ALEN);
                    memcpy(requestEthHeader.ether_shost, reqEthHeader->ether_shost, ETH_ALEN);
                    requestEthHeader.ether_type = reqEthHeader->ether_type;
                }

                if(requestFiltered == TRUE)
                {
                    if(FilterResponse(socketFd, targetIP, httpResponsePacket) == NO_ERROR)
                    {
                        std::cout << "original response:\n";
                        httpResponsePacket.Print();

                        PacketCraft::Packet newResponse;
                        CreateResponse(httpResponsePacket, newResponse, newDownloadLink);

                        std::cout << "new response:\n";
                        newResponse.Print();

                        if(newResponse.Send(socketFd, interfaceName, 0) == APPLICATION_ERROR)
                        {
                            LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::Send() errpr");
                            return APPLICATION_ERROR;
                        }

                        requestFiltered = FALSE;
                    }
                }
            }
        }
    }
}

int CHaks::FileInterceptor::FilterRequest(const int socketFd, const char* targetIP, const char* downloadLink, PacketCraft::Packet& httpRequestPacket)
{
    if(httpRequestPacket.Receive(socketFd, 0) == APPLICATION_ERROR)
    {
        // LOG_ERROR(APPLICATION_WARNING, "PacketCraft::Packet::Receive() error");
        return APPLICATION_WARNING;
    }

    char* httpRequest = (char*)httpRequestPacket.FindLayerByType(PC_HTTP_REQUEST);
    if(httpRequest != nullptr)
    {
        if(PacketCraft::GetHTTPMethod((uint8_t*)httpRequest) == PC_HTTP_GET)
        {
            // check that IP matches the desired target
            if(ipVersion == AF_INET)
            {
                sockaddr_in targetIPAddr{};
                if(inet_pton(AF_INET, targetIP, &targetIPAddr.sin_addr) == -1)
                {
                    LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
                    return APPLICATION_ERROR;
                }

                IPv4Header* ipv4Header = (IPv4Header*)httpRequestPacket.FindLayerByType(PC_IPV4);
                if(ipv4Header->ip_src.s_addr != targetIPAddr.sin_addr.s_addr)
                    return APPLICATION_WARNING;
            }
            else
            {
                sockaddr_in6 targetIPAddr{};
                if(inet_pton(AF_INET6, targetIP, &targetIPAddr.sin6_addr) == -1)
                {
                    LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
                    return APPLICATION_ERROR;
                }

                IPv6Header* ipv6Header = (IPv6Header*)httpRequestPacket.FindLayerByType(PC_IPV6);
                if(memcmp(ipv6Header->ip6_src.__in6_u.__u6_addr8, targetIPAddr.sin6_addr.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
                    return APPLICATION_WARNING;
            }
            ////////////////////

            char packetFileName[255]{};
            char packetDomainName[255]{};
            char packetDownloadLink[1024]{};

            char buffer[255]{};

            // Copy the first line of the http request in buffer. Should be something like this: "GET /test/file.php HTTP/1.1"
            PacketCraft::CopyStrUntil(buffer, sizeof(buffer), httpRequest, '\n');

            int filePathStartIndex = 4;
            int filePathEndIndex = PacketCraft::FindInStr(buffer, " HTTP");
            memcpy(packetFileName, buffer + filePathStartIndex, filePathEndIndex - filePathStartIndex);
            memset(buffer, '\0', sizeof(buffer));
            packetFileName[filePathEndIndex] = '\0';

            // Copy the line containing the host domain name in buffer. Should be something like this: "Host: example.test.com"
            PacketCraft::CopyStrUntil(buffer, sizeof(buffer), httpRequest + PacketCraft::FindInStr(httpRequest, "Host: "), '\n');

            int domainStartIndex = 6;
            int domainEndIndex = PacketCraft::FindInStr(buffer, "\r\n");
            memcpy(packetDomainName, buffer + domainStartIndex, domainEndIndex - domainStartIndex);
            memset(buffer, '\0', sizeof(buffer));
            packetDomainName[domainEndIndex] = '\0';

            PacketCraft::ConcatStr(packetDownloadLink, sizeof(packetDownloadLink), packetDomainName, packetFileName);

            if(PacketCraft::CompareStr(packetDownloadLink, downloadLink) == TRUE)
            {
                TCPHeader* tcpHeader = (TCPHeader*)httpRequestPacket.FindLayerByType(PC_TCP);
                if(tcpHeader == nullptr)
                {
                    LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::FindLayerByType() error");
                    return APPLICATION_ERROR;
                }

                // valid request found
                requestAckNum = tcpHeader->ack_seq;
                return NO_ERROR;
            }
        }
    }

    return APPLICATION_WARNING;
}

int CHaks::FileInterceptor::FilterResponse(const int socketFd, const char* targetIP, PacketCraft::Packet& httpResponsePacket)
{
    if(httpResponsePacket.Receive(socketFd, 0) == APPLICATION_ERROR)
    {
        // LOG_ERROR(APPLICATION_WARNING, "PacketCraft::Packet::Receive() error");
        return APPLICATION_WARNING;
    }

    char* httpResponse = (char*)httpResponsePacket.FindLayerByType(PC_HTTP_RESPONSE);
    if(httpResponse != nullptr)
    {
        if(PacketCraft::GetHTTPMethod((uint8_t*)httpResponse) == PC_HTTP_SUCCESS)
        {
            // check that IP matches the desired target
            if(ipVersion == AF_INET)
            {
                sockaddr_in targetIPAddr{};
                if(inet_pton(AF_INET, targetIP, &targetIPAddr.sin_addr) == -1)
                {
                    LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
                    return APPLICATION_ERROR;
                }

                IPv4Header* ipv4Header = (IPv4Header*)httpResponsePacket.FindLayerByType(PC_IPV4);
                if(ipv4Header->ip_dst.s_addr != targetIPAddr.sin_addr.s_addr)
                    return APPLICATION_WARNING;
            }
            else
            {
                sockaddr_in6 targetIPAddr{};
                if(inet_pton(AF_INET6, targetIP, &targetIPAddr.sin6_addr) == -1)
                {
                    LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
                    return APPLICATION_ERROR;
                }

                IPv6Header* ipv6Header = (IPv6Header*)httpResponsePacket.FindLayerByType(PC_IPV6);
                if(memcmp(ipv6Header->ip6_dst.__in6_u.__u6_addr8, targetIPAddr.sin6_addr.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
                    return APPLICATION_WARNING;
            }
            ////////////////////

            TCPHeader* tcpHeader = (TCPHeader*)httpResponsePacket.FindLayerByType(PC_TCP);
            if(tcpHeader == nullptr)
            {
                LOG_ERROR(APPLICATION_ERROR, "could not find tcp layer");
                return APPLICATION_ERROR;
            }

            // response matching the original request found
            if(tcpHeader->seq == requestAckNum)
                return NO_ERROR;
        }
    }

    return APPLICATION_WARNING;
}

int CHaks::FileInterceptor::CreateResponse(const PacketCraft::Packet& originalResponse, PacketCraft::Packet& newResponse, const char* newDownloadLink) const
{
    newResponse.AddLayer(PC_ETHER_II, ETH_HLEN);
    EthHeader* newResponseEthHeader = (EthHeader*)newResponse.GetLayerStart(0);
    memcpy(newResponseEthHeader->ether_dhost, requestEthHeader.ether_shost, ETH_ALEN);
    memcpy(newResponseEthHeader->ether_shost, requestEthHeader.ether_dhost, ETH_ALEN);
    newResponseEthHeader->ether_type = requestEthHeader.ether_type;

    if(ipVersion == AF_INET)
    {
        IPv4Header* originalResponseIPv4Header = (IPv4Header*)originalResponse.FindLayerByType(PC_IPV4);
        newResponse.AddLayer(PC_IPV4, sizeof(IPv4Header));
        IPv4Header* newResponseIPv4Header = (IPv4Header*)newResponse.FindLayerByType(PC_IPV4);
        newResponseIPv4Header->ip_v = originalResponseIPv4Header->ip_v;
        newResponseIPv4Header->ip_hl = 5;
        newResponseIPv4Header->ip_tos = 0;
        newResponseIPv4Header->ip_len = htons(0); // calculated after packet has been constructed completely
        newResponseIPv4Header->ip_id = originalResponseIPv4Header->ip_id;
        newResponseIPv4Header->ip_off = IP_DF;
        newResponseIPv4Header->ip_ttl = originalResponseIPv4Header->ip_ttl;
        newResponseIPv4Header->ip_p = originalResponseIPv4Header->ip_p;
        newResponseIPv4Header->ip_sum = htons(0);
        newResponseIPv4Header->ip_src.s_addr = originalResponseIPv4Header->ip_src.s_addr;
        newResponseIPv4Header->ip_dst.s_addr = originalResponseIPv4Header->ip_dst.s_addr;
    }
    else
    {
        IPv6Header* originalResponseIPv6Header = (IPv6Header*)originalResponse.FindLayerByType(PC_IPV6);
        newResponse.AddLayer(PC_IPV6, sizeof(IPv6Header));
        IPv6Header* newResponseIPv6Header = (IPv6Header*)newResponse.FindLayerByType(PC_IPV6);
        newResponseIPv6Header->ip6_ctlun.ip6_un1.ip6_un1_flow = originalResponseIPv6Header->ip6_ctlun.ip6_un1.ip6_un1_flow;
        newResponseIPv6Header->ip6_ctlun.ip6_un1.ip6_un1_hlim = originalResponseIPv6Header->ip6_ctlun.ip6_un1.ip6_un1_hlim;
        newResponseIPv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;
        newResponseIPv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(0); // calculated after packet has been constructed completely
        memcpy(newResponseIPv6Header->ip6_src.__in6_u.__u6_addr8, originalResponseIPv6Header->ip6_src.__in6_u.__u6_addr8, IPV6_ALEN);
        memcpy(newResponseIPv6Header->ip6_dst.__in6_u.__u6_addr8, originalResponseIPv6Header->ip6_dst.__in6_u.__u6_addr8, IPV6_ALEN);
    }

    TCPHeader* originalResponseTCPHeader = (TCPHeader*)originalResponse.FindLayerByType(PC_TCP);
    newResponse.AddLayer(PC_TCP, sizeof(TCPHeader));
    TCPHeader* newResponseTCPHeader = (TCPHeader*)newResponse.FindLayerByType(PC_TCP);
    newResponseTCPHeader->source = originalResponseTCPHeader->source;
    newResponseTCPHeader->dest = originalResponseTCPHeader->dest;
    newResponseTCPHeader->seq = originalResponseTCPHeader->seq;
    newResponseTCPHeader->ack_seq = originalResponseTCPHeader->ack_seq;
    newResponseTCPHeader->doff = originalResponseTCPHeader->doff;
    newResponseTCPHeader->res1 = originalResponseTCPHeader->res1;
    newResponseTCPHeader->fin = originalResponseTCPHeader->fin;
    newResponseTCPHeader->syn = originalResponseTCPHeader->syn;
    newResponseTCPHeader->rst = originalResponseTCPHeader->rst;
    newResponseTCPHeader->psh = originalResponseTCPHeader->psh;
    newResponseTCPHeader->ack = originalResponseTCPHeader->ack;
    newResponseTCPHeader->urg = originalResponseTCPHeader->urg;
    newResponseTCPHeader->res2 = originalResponseTCPHeader->res2;
    newResponseTCPHeader->window = originalResponseTCPHeader->window;
    newResponseTCPHeader->check = htons(0);
    newResponseTCPHeader->urg_ptr = originalResponseTCPHeader->urg_ptr;

    const char* httpStatusCode = "HTTP/1.1 301 Moved Permanently\r\nLocation: ";
    uint32_t responseCodeLen = PacketCraft::GetStrLen(httpStatusCode) + PacketCraft::GetStrLen(newDownloadLink) + 1;
    char* fullHTTPCode = (char*)malloc(responseCodeLen);
    PacketCraft::ConcatStr(fullHTTPCode, responseCodeLen, httpStatusCode, newDownloadLink);

    newResponse.AddLayer(PC_HTTP_RESPONSE, responseCodeLen - 1);
    memcpy(newResponse.GetLayerStart(newResponse.GetNLayers() - 1), fullHTTPCode, responseCodeLen - 1);

    if(ipVersion == AF_INET)
    {
        IPv4Header* ipv4Header = (IPv4Header*)newResponse.FindLayerByType(PC_IPV4);
        ipv4Header->ip_len = htons(newResponse.GetSizeInBytes() - ETH_HLEN);
    }
    else
    {
        IPv6Header* ipv6Header = (IPv6Header*)newResponse.FindLayerByType(PC_IPV6);
        ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(newResponse.GetSizeInBytes() - sizeof(EthHeader) - sizeof(IPv6Header)); // TODO: test
    }

    newResponse.CalculateChecksums();

    return NO_ERROR;
}