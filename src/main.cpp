// general C++ stuff
#include <iostream>

// general C stuff
#include <stdlib.h>
#include <cstring>

// network stuff
#include <netinet/in.h>
#include <arpa/inet.h>

// packet craft
#include "ARP.h"
#include "Utils.h"


int main(int argc, char** argv)
{
    // DEST INFO
    const char* dstMACStr = "ff:ff:ff:ff:ff:ff";
    const char* dstIPStr = "10.0.2.4";

    ether_addr dstMAC;
    ether_aton_r(dstMACStr, &dstMAC);

    sockaddr_in dstIP;
    inet_pton(AF_INET, dstIPStr, &dstIP.sin_addr);
    ////////////////////

    int mySocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(mySocket < 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    ether_addr srcMAC;
    PacketCraft::GetMACAddr(srcMAC, "eth0", mySocket);
    PacketCraft::PrintMACAddr(srcMAC, "source MAC: ", "\n");

    sockaddr_in srcIP;
    PacketCraft::GetIPAddr(srcIP, "eth0");
    PacketCraft::PrintIPAddr(srcIP, "source IP: ", "\n");

    PacketCraft::ARPPacket arpPacket;
    arpPacket.Create(srcMAC, dstMAC, srcIP, dstIP, ARPType::ARP_REQUEST);
    arpPacket.Send(mySocket, "eth0");

    // ARP packet test
    /*
    PacketCraft::Packet packet;

    packet.AddLayer(PC_ETHER_II, sizeof(ether_header));
    ether_header* ethHeader = (ether_header*)packet.GetLayerStart(0);
    memcpy(ethHeader->ether_shost, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(ethHeader->ether_dhost, dstMAC.ether_addr_octet, ETH_ALEN);
    ethHeader->ether_type = htons(ETH_P_ARP);

    packet.AddLayer(PC_ARP_REQUEST, sizeof(ARPHeader));
    ARPHeader* arpHeader = (ARPHeader*)packet.GetLayerStart(1);
    arpHeader->arpHdr.ar_hrd = htons(ARPHRD_ETHER);
    arpHeader->arpHdr.ar_pro = htons(ETH_P_IP);
    arpHeader->arpHdr.ar_hln = ETH_ALEN;
    arpHeader->arpHdr.ar_pln = IPV4_ALEN;
    arpHeader->arpHdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(arpHeader->ar_sha, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_sip, &srcIP.sin_addr.s_addr, IPV4_ALEN);
    memcpy(arpHeader->ar_tha, dstMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_tip, &dstIP.s_addr, IPV4_ALEN);

    sockaddr_ll sockAddr;
    sockAddr.sll_family = PF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_ARP);
    sockAddr.sll_ifindex = 2;
    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    sockAddr.sll_halen = ETH_ALEN;

    packet.Send(mySocket, 0, (sockaddr*)&sockAddr, sizeof(sockAddr));
    */


    return NO_ERROR;
}

