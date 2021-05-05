#ifndef PC_UTILS_H
#define PC_UTILS_H

#include "PCTypes.h"

#ifdef DEBUG_BUILD
#define LOG_ERROR(errorCode, msg) PacketCraft::PrintError((errorCode), (__PRETTY_FUNCTION__), (msg))
#else
    #define LOG_ERROR(errorCode, msg)
#endif

#define BIT_CHECK(value, nthBit) PacketCraft::CheckBit((value), (nthBit))

namespace PacketCraft
{
    // String utils
    int GetStrLen(const char* str);
    void CopyStr(char* dest, size_t destSize, const char* src);
    bool32 CompareStr(const char* str1, const char* str2);
    int FindInStr(const char* str, const char* pattern);

    // Debug utils
    void PrintError(const int errorCode, const char* func, const char* msg);

    // Other
    bool32 CheckBit(const int val, const int nthBit);
}

#endif