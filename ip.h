#include <optional>
#include <string>

// canonical IP is ipv6 expressed uncompressed as 16 bytes
struct IP  
{
    uint8_t b[16];
};
struct IPComparator
{
    bool operator()(const std::pair<IP, int>& lhs, const std::pair<IP, int>& rhs) const
    {
        int rc = memcmp(&lhs.first, &rhs.first, 16);
        return (rc < 0 || rc == 0 && lhs.second < rhs.second);
    }
    bool operator()(const IP& lhs, const IP& rhs) const
    {
        return memcmp(&lhs, &rhs, 16) < 0;
    }
};

std::optional<std::pair<IP, int>> parse_endpoint(const char* endpoint, int len);
std::optional<IP> canonicalize_ip(const char* ip_str);
std::string str_ip(IP const& ip);
std::string str_ip(uint8_t* ip);

