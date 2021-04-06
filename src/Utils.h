#ifndef PC_UTILS_H
#define PC_UTILS_H

#include <sys/types.h>

#define TRUE                1
#define FALSE               0

#define NO_ERROR            0
#define APPLICATION_ERROR   1      

#define ETH_ADDR_STR_LEN    17

#ifdef DEBUG_BUILD
#define LOG_ERROR(errorCode, msg) PacketCraft::PrintError((errorCode), (__FUNCTION__), (msg))
#else
    #define LOG_ERROR(errorCode, msg)
#endif

typedef int32_t bool32;

struct ether_addr;
struct sockaddr_in;
struct sockaddr_in6;
struct sockaddr_storage;

namespace PacketCraft
{
    // Network utils
    int GetMACAddr(ether_addr& ethAddr, const char* interfaceName, const int socketFd);
    int GetMACAddr(ether_addr& ethAddr, const int interfaceIndex, const int socketFd);
    int GetIPAddr(sockaddr_in& addr, const char* interfaceName);
    int GetIPAddr(sockaddr_in6& addr, const char* interfaceName);
    int GetIPAddr(sockaddr_storage& addr, const char* interfaceName);

    int PrintIPAddr(const sockaddr_storage& addr, const char* end = "");
    int PrintIPAddr(const sockaddr_in& addr, const char* end = "");
    int PrintIPAddr(const sockaddr_in6& addr, const char* end = "");
    int PrintMACAddr(const ether_addr& addr, const char* end = "");

    // String utils
    int GetStrLen(const char* str);
    void CopyStr(char* dest, size_t destSize, const char* src);
    bool32 CompareStr(const char* str1, const char* str2);
    int FindInStr(const char* str, const char* pattern);

    // Debug utils
    void PrintError(const int errorCode, const char* func, const char* msg);
}

#endif