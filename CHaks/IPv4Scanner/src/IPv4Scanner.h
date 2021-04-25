#ifndef IPV4_SCANNER_H
#define IPV4_SCANNER_H

namespace IPv4Scan
{
    class IPv4Scanner
    {
        public:
        IPv4Scanner();
        ~IPV4Scanner();

        void Scan(const sockaddr_in& networkAddr);
    }
}

#endif