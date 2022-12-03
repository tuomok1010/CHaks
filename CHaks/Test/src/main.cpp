#include "../../../../PacketCraft/PacketCraft/src/include/PCInclude.h"

#include <iostream>
#include <memory>
#include <functional>
#include <array>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <poll.h>
#include <cstring>

extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
}

  
static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    if(ph == nullptr)
    {
        nfq_destroy_queue(queue);
        nfq_close((nfq_handle*)data); // note we passed this handle into this callback function when we called nfq_create_queue()
        LOG_ERROR(APPLICATION_ERROR, "nfq_get_msg_packet_hdr() error");
        return APPLICATION_ERROR;
    }
  
    unsigned char* rawData = nullptr;
    int len = nfq_get_payload(nfad, &rawData);
    if(len < 0)
    {
        nfq_destroy_queue(queue);
        nfq_close((nfq_handle*)data); // note we passed this into this callback function when we called nfq_create_queue()
        LOG_ERROR(APPLICATION_ERROR, "nfq_get_payload() error");
        return APPLICATION_ERROR;
    }

    std::cout << "packet with the id " << ntohl(ph->packet_id) << " received (" << len << ") bytes\n";
  
    struct pkt_buff* pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
    if(pkBuff == nullptr)
    {
        nfq_destroy_queue(queue);
        nfq_close((nfq_handle*)data); // note we passed this into this callback function when we called nfq_create_queue()
        pktb_free(pkBuff);
        LOG_ERROR(APPLICATION_ERROR, "pktb_alloc() error");
        return APPLICATION_ERROR;
    }
  
    struct iphdr* ip = nfq_ip_get_hdr(pkBuff);
    if(ip == nullptr)
    {
        nfq_destroy_queue(queue);
        nfq_close((nfq_handle*)data); // note we passed this into this callback function when we called nfq_create_queue()
        pktb_free(pkBuff);
        LOG_ERROR(APPLICATION_ERROR, "nfq_ip_get_hdr() error");
        return APPLICATION_ERROR;
    }

    if(nfq_ip_set_transport_header(pkBuff, ip) < 0)
    {
        nfq_destroy_queue(queue);
        nfq_close((nfq_handle*)data); // note we passed this into this callback function when we called nfq_create_queue()
        pktb_free(pkBuff);
        LOG_ERROR(APPLICATION_ERROR, "nfq_ip_set_transport_header() error");
        return APPLICATION_ERROR;
    }
      
    if(ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
        if(tcp == nullptr)
        {
            nfq_destroy_queue(queue);
            nfq_close((nfq_handle*)data); // note we passed this into this callback function when we called nfq_create_queue()
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_get_hdr() error");
            return APPLICATION_ERROR;
        }
          
        void *payload = nfq_tcp_get_payload(tcp, pkBuff);
        if(payload == nullptr)
        {
            nfq_destroy_queue(queue);
            nfq_close((nfq_handle*)data); // note we passed this into this callback function when we called nfq_create_queue()
            pktb_free(pkBuff);
            LOG_ERROR(APPLICATION_ERROR, "nfq_tcp_get_payload() error");
            return APPLICATION_ERROR;
        }

        unsigned int payloadLen = nfq_tcp_get_payload_len(tcp, pkBuff);
        payloadLen -= 4 * tcp->th_off;
  
        // note here we could edit the tcp header and payload if we wanted to
          
        nfq_tcp_compute_checksum_ipv4(tcp, ip);
        return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
    }
    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
}

int ProcessArgs(int argc, char** argv, int& queueNum)
{
    if(argc != 2)
        return APPLICATION_ERROR;

    queueNum = atoi(argv[1]);
    return NO_ERROR;
}
  
void flushAndRemoveTablesAndChains(const char* ipVersion, const char* tableName)
{
    char cmd[1024]{};
    // flush and remove table
    snprintf(cmd, 1024, "nft flush table %s %s", ipVersion, tableName);
    system(cmd);
    memset(cmd, 0, 1024);
    snprintf(cmd, 2014, "nft delete table %s %s", ipVersion, tableName);
    system(cmd);
    /////////////
}
  
int main(int argc, char** argv)
{
    int queueNum{0};
    if(ProcessArgs(argc, argv, queueNum) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "invalid args");
        return APPLICATION_ERROR;
    }

    char cmd[1024]{};
    if(system("nft add table ip filter") != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system(nft add table ip filter) error");
        return APPLICATION_ERROR;
    }
    if(system("nft 'add chain ip filter postrouting { type filter hook postrouting priority 0 ; }'") != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system(nft 'add chain ip filter postrouting { type filter hook postrouting priority 0 ; }') error");
        return APPLICATION_ERROR;
    }
    snprintf(cmd, 1024, "nft add rule filter postrouting counter queue num %d", queueNum);
    if(system(cmd) != 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "system(nft add filter postrouting counter queue num) error");
        return APPLICATION_ERROR;
    }

    struct nfq_handle * handler = nfq_open();
    if(handler == nullptr)
    {
        nfq_close(handler);
        flushAndRemoveTablesAndChains("ip", "filter");
        LOG_ERROR(APPLICATION_ERROR, "nfq_open() error");
        return APPLICATION_ERROR;
    }
  
    struct nfq_q_handle *queue = nfq_create_queue(handler, queueNum, netfilterCallback, handler);
    if(queue == nullptr)
    {
        nfq_destroy_queue(queue);
        nfq_close(handler);
        flushAndRemoveTablesAndChains("ip", "filter");
        LOG_ERROR(APPLICATION_ERROR, "nfq_create_queue() error");
        return APPLICATION_ERROR;
    }

    if(nfq_set_mode(queue, NFQNL_COPY_PACKET, UINT16_MAX) < 0)
    {
        nfq_destroy_queue(queue);
        nfq_close(handler);
        flushAndRemoveTablesAndChains("ip", "filter");
        LOG_ERROR(APPLICATION_ERROR, "nfq_set_mode() error");
        return APPLICATION_ERROR;
    }
  
    int socketFd = nfq_fd(handler);
    char buffer[IP_MAXPACKET]{};
    struct pollfd pollFds[2];
    pollFds[0].fd = 0;
    pollFds[0].events = POLLIN;
    pollFds[1].fd = socketFd;
    pollFds[1].events = POLLIN;

    for(;;)
    {
        int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), -1);
        if(nEvents == -1)
        {
            nfq_destroy_queue(queue);
            nfq_close(handler);
            if(socketFd > 0)
                close(socketFd);

            flushAndRemoveTablesAndChains("ip", "filter");
            LOG_ERROR(APPLICATION_ERROR, "poll() error");
            return APPLICATION_ERROR;
        }
        else
        {
            if(pollFds[0].revents & POLLIN) 
            {
                break;
            }
            else if(pollFds[1].revents & POLLIN)
            {
                int len = read(pollFds[1].fd, buffer, IP_MAXPACKET);
                if(len < 0)
                {
                    nfq_destroy_queue(queue);
                    nfq_close(handler);
                    close(socketFd);
                    flushAndRemoveTablesAndChains("ip", "filter");

                    LOG_ERROR(APPLICATION_ERROR, "read() error");
                    return APPLICATION_ERROR;
                }

                nfq_handle_packet(handler, buffer, len);
            }
        }
    }

    nfq_destroy_queue(queue);
    nfq_close(handler);
    close(socketFd);
    flushAndRemoveTablesAndChains("ip", "filter");
    std::cout << "quitting..." << std::endl;
    return NO_ERROR;
 } 