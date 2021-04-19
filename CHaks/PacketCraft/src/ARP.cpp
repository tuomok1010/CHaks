#include "ARP.h"
#include "Utils.h"

#include <iostream>

#include <cstring>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

PacketCraft::ARPPacket::ARPPacket():
    ethHeader(nullptr),
    arpHeader(nullptr)
{

}

PacketCraft::ARPPacket::~ARPPacket()
{
    FreePacket();
}

int PacketCraft::ARPPacket::Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, ARPType type)
{
    FreePacket();

    AddLayer(PC_ETHER_II, ETH_HLEN);
    ethHeader = (ether_header*)GetLayerStart(0);
    memcpy(ethHeader->ether_shost, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(ethHeader->ether_dhost, dstMAC.ether_addr_octet, ETH_ALEN);
    ethHeader->ether_type = htons(ETH_P_ARP);

    AddLayer(PC_ARP, sizeof(ARPHeader));
    arpHeader = (ARPHeader*)GetLayerStart(1);
    arpHeader->ar_hrd = htons(ARPHRD_ETHER);
    arpHeader->ar_pro = htons(ETH_P_IP);
    arpHeader->ar_hln = ETH_ALEN;
    arpHeader->ar_pln = IPV4_ALEN;
    arpHeader->ar_op = htons(type == ARPType::ARP_REQUEST ? ARPOP_REQUEST : ARPOP_REPLY);
    memcpy(arpHeader->ar_sha, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_sip, &srcIP.sin_addr.s_addr, IPV4_ALEN);
    memcpy(arpHeader->ar_tha, dstMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_tip, &dstIP.sin_addr.s_addr, IPV4_ALEN);


    // eth layer for printing
    ether_addr srcMACEth{};
    char srcMACStr[ETH_ADDR_STR_LEN]{};
    ether_addr dstMACEth{};
    char dstMACStr[ETH_ADDR_STR_LEN]{};
    uint16_t ethType = ntohs(ethHeader->ether_type);
    memcpy(srcMACEth.ether_addr_octet, ethHeader->ether_shost, ETH_ALEN);
    ether_ntoa_r(&srcMACEth, srcMACStr);
    memcpy(dstMACEth.ether_addr_octet, ethHeader->ether_dhost, ETH_ALEN);
    ether_ntoa_r(&dstMACEth, dstMACStr);

    std::cout 
        << "ARPPacket::Create() eth layer:\n"
        << "src MAC: " << srcMACStr << "\n"
        << "dst MAC: " << dstMACStr << "\n"
        << "ether type: " << ethType << "\n" << std::endl;

    // arp layer for printing
    ether_addr srcMACArp{};
    char srcMACArpStr[ETH_ADDR_STR_LEN]{};
    ether_addr dstMACArp{};
    char dstMACArpStr[ETH_ADDR_STR_LEN]{};
    memcpy(srcMACArp.ether_addr_octet, arpHeader->ar_sha, ETH_ALEN);
    ether_ntoa_r(&srcMACArp, srcMACArpStr);
    memcpy(dstMACArp.ether_addr_octet, arpHeader->ar_tha, ETH_ALEN);
    ether_ntoa_r(&dstMACArp, dstMACArpStr);
    char srcIPArpStr[INET_ADDRSTRLEN]{};
    char dstIPArpStr[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, arpHeader->ar_sip, srcIPArpStr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arpHeader->ar_tip, dstIPArpStr, INET_ADDRSTRLEN);
    uint16_t ar_hrd = ntohs(arpHeader->ar_hrd);    
    uint16_t ar_pro = ntohs(arpHeader->ar_pro);    
    uint32_t ar_hln = /*arpHeader->ar_hln*/ 5;             
    uint32_t ar_pln = /*arpHeader->ar_pln*/ 10;             
    uint16_t ar_op = ntohs(arpHeader->ar_op);

    std::cout
        << "ARPPacket::Create() arp layer:\n"
        << "hardware format: " << ar_hrd << "\n"
        << "protocol format: " << ar_pro << "\n"
        << "hardware length: " << ar_hln << "\n"
        << "protocol length: " << ar_pln << "\n"
        << "opcode: " << ar_op << "\n"
        << "src mac: " << srcMACArpStr << "\n"
        << "src ip: " << srcIPArpStr << "\n"
        << "dst mac: " << dstMACArpStr << "\n"
        << "src ip: " << dstIPArpStr << "\n" << std::endl;

    return NO_ERROR;
}

int PacketCraft::ARPPacket::Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, ARPType type)
{
    ether_addr srcMAC{};
    ether_addr dstMAC{};
    sockaddr_in srcIP{};
    sockaddr_in dstIP{};

    if(ether_aton_r(srcMACStr, &srcMAC) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_aton_r(dstMACStr, &dstMAC) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    if(inet_pton(AF_INET, srcIPStr, &srcIP.sin_addr) <= 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    if(inet_pton(AF_INET, dstIPStr, &dstIP.sin_addr) <= 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    return Create(srcMAC, dstMAC, srcIP, dstIP, type);
}

int PacketCraft::ARPPacket::Send(const int socket, const char* interfaceName) const
{
    int ifIndex = if_nametoindex(interfaceName);
    if(ifIndex == 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "if_nametoindex() error!");
        return APPLICATION_ERROR;
    }

    sockaddr_ll sockAddr;
    sockAddr.sll_family = PF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_ARP);
    sockAddr.sll_ifindex = ifIndex;
    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    sockAddr.sll_halen = ETH_ALEN;

    return Packet::Send(socket, 0, (sockaddr*)&sockAddr, sizeof(sockAddr));
}

void PacketCraft::ARPPacket::FreePacket()
{
    PacketCraft::Packet::FreePacket();
    ethHeader = nullptr;
    arpHeader = nullptr;
}

int PacketCraft::ARPPacket::PrintPacketData() const
{
    if(ethHeader == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ethHeader is null!");
        return APPLICATION_ERROR;
    }
    if(arpHeader == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "arpHeader is null!");
        return APPLICATION_ERROR;
    }

    char ethDstAddr[ETH_ADDR_STR_LEN]{};                                /* destination eth addr	*/
    char ethSrcAddr[ETH_ADDR_STR_LEN]{};                                /* source ether addr	*/
    uint16_t ether_type = ntohs(ethHeader->ether_type);		            /* packet type ID field	*/

    ether_addr ethHdrDstAddr{};
    memcpy(ethHdrDstAddr.ether_addr_octet, ethHeader->ether_dhost, ETH_ALEN);
    if(ether_ntoa_r(&ethHdrDstAddr, ethDstAddr) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    ether_addr ethHdrSrcAddr{};
    memcpy(ethHdrSrcAddr.ether_addr_octet, ethHeader->ether_shost, ETH_ALEN);
    if(ether_ntoa_r(&ethHdrSrcAddr, ethSrcAddr) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    // IMPORTANT: casting arpHeader->ar_hln and arpHeader->ar_pln into a uint16_t because
    //            std::cout doesn't print uint8_t properly!!!
    uint16_t ar_hrd = ntohs(arpHeader->ar_hrd);     /* Format of hardware address.  */
    uint16_t ar_pro = ntohs(arpHeader->ar_pro);     /* Format of protocol address.  */
    uint16_t ar_hln = (uint16_t)arpHeader->ar_hln;  /* Length of hardware address.  */
    uint16_t ar_pln = (uint16_t)arpHeader->ar_pln;  /* Length of protocol address.  */
    uint16_t ar_op = ntohs(arpHeader->ar_op);		/* ARP opcode (command).  */

    char ar_sha[ETH_ADDR_STR_LEN]{};                /* Sender hardware address.  */
    char ar_sip[INET_ADDRSTRLEN]{};                 /* Sender IP address.  */
    char ar_tha[ETH_ADDR_STR_LEN]{};                /* Target hardware address.  */
    char ar_tip[INET_ADDRSTRLEN]{};                 /* Target IP address.  */

    if(inet_ntop(AF_INET, arpHeader->ar_sip, ar_sip, INET_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    if(inet_ntop(AF_INET, arpHeader->ar_tip, ar_tip, INET_ADDRSTRLEN) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    ether_addr senderMACAddr{};
    memcpy(senderMACAddr.ether_addr_octet, arpHeader->ar_sha, ETH_ALEN);
    if(ether_ntoa_r(&senderMACAddr, ar_sha) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    ether_addr targetMACAddr{};
    memcpy(targetMACAddr.ether_addr_octet, arpHeader->ar_tha, ETH_ALEN);
    if(ether_ntoa_r(&targetMACAddr, ar_tha) == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    // TODO: format nicely with iomanip perhaps?
    std::cout
        << " = = = = = = = = = = = = = = = = = = = = \n"
        << "[ETHERNET]:\n"
        << "destination: "          << ethDstAddr   << "\n"
        << "source: "               << ethSrcAddr   << "\n"
        << "type: "                 << ether_type   << "\n"
        << " - - - - - - - - - - - - - - - - - - - - \n"
        << "[ARP]:\n"
        << "hardware type: "        << ar_hrd       << "\n"
        << "protocol type: "        << ar_pro       << "\n"
        << "hardware size: "        << ar_hln       << "\n"
        << "protocol size: "        << ar_pln       << "\n"
        << "op code: "              << ar_op        << " (" << (ar_op == 1 ? "request" : "reply") << ")\n"
        << "sender MAC address: "   << ar_sha       << "\n"
        << "sender IP address: "    << ar_sip       << "\n"
        << "target MAC address: "   << ar_tha       << "\n"
        << "target IP address: "    << ar_tip       << "\n"
        << " = = = = = = = = = = = = = = = = = = = = " << std::endl;

    return NO_ERROR;
}

// TODO: extensive testing! This needs to be bulletproof!!!
int PacketCraft::ARPPacket::ProcessReceivedPacket(uint8_t* packet, unsigned short protocol)
{
    switch(protocol)
    {
        case 0:
        {
            AddLayer(PC_ETHER_II, ETH_HLEN);
            memcpy(GetData(), packet, ETH_HLEN);
            protocol = ntohs(((ether_header*)packet)->ether_type);
            ethHeader = (ether_header*)GetLayerStart(GetNLayers() - 1);

            ether_addr ethAddrSrc{};
            memcpy(ethAddrSrc.ether_addr_octet, ethHeader->ether_shost, ETH_ALEN);
            char ethHdrSrcMacStr[ETH_ADDR_STR_LEN]{};
            ether_ntoa_r(&ethAddrSrc, ethHdrSrcMacStr);
            ether_addr ethAddrDst{};
            memcpy(ethAddrDst.ether_addr_octet, ethHeader->ether_dhost, ETH_ALEN);
            char ethHdrDstMacStr[ETH_ADDR_STR_LEN]{};
            ether_ntoa_r(&ethAddrDst, ethHdrDstMacStr);
            uint16_t eType = ntohs(ethHeader->ether_type);

            std::cout <<  "ProcessReceivedPacket() ether type: " << eType << std::endl;
            std::cout << "ProcessReceivedPacket() src mac: " << ethHdrSrcMacStr << std::endl;
            std::cout << "ProcessReceivedPacket() dst mac: " << ethHdrDstMacStr << std::endl;

            packet += ETH_HLEN;
            break;
        }
        case ETH_P_ARP:
        {
            AddLayer(PC_ARP, sizeof(ARPHeader));
            memcpy(GetLayerStart(GetNLayers() - 1), packet, sizeof(ARPHeader));
            arpHeader = (ARPHeader*)GetLayerStart(GetNLayers() - 1);
            return NO_ERROR;
        }
        default:
        {
            FreePacket();
            LOG_ERROR(APPLICATION_ERROR, "unsupported packet layer type received! Packet data cleared.");
            return APPLICATION_ERROR;
        }
    }

    return ProcessReceivedPacket(packet, protocol);

}