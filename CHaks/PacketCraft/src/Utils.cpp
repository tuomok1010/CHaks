#include "Utils.h"

#include <iostream>

// General utils
int PacketCraft::GetStrLen(const char* str)
{
    int counter{};
    while(str[counter++] != '\0')
        continue;
    return counter -1;
}

void PacketCraft::CopyStr(char* dest, size_t destSize, const char* src)
{
    for(size_t i = 0; i < destSize; ++i)
    {
        dest[i] = src[i];
        if(src[i] == '\0')
            break;
    }
}

bool32 PacketCraft::CompareStr(const char* str1, const char* str2)
{
    while((*str1++ == *str2++))
    {
        if(*str1 == '\0')
            return TRUE;
    }

    return FALSE;
}

// If pattern string is found in str, returns the index. If it is not found returns -1
int PacketCraft::FindInStr(const char* str, const char* pattern)
{
    int foundIndex{};
    while(*str != '\0')
    {
        const char* c1 = str;
        const char* c2 = pattern;

        while(*c1++ == *c2++)
        {
            if(*c2 == '\0')
            {
                return foundIndex;
            }
        }
        ++str;
        ++foundIndex;
    }
    return -1;
}


// Debug utils
void PacketCraft::PrintError(const int errorCode, const char* func, const char* msg)
{
    switch(errorCode)
    {
        case APPLICATION_ERROR:
        {
            std::cerr << "APPLICATION ERROR in function: " << func << ". Error message: " << msg << std::endl;
        } break;

        default:
        {
            std::cerr << "UNKNOWN ERROR in function: " << func << ". Error message: " << msg << std::endl;
        }
    }
}