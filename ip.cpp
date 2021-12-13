#include "uplink.h"

// parse any ip (4 or 6) into a 16 byte ipv6 address
std::optional<IP> canonicalize_ip(const char* ip_str)
{
    IP out;
    uint8_t* ip_int = &(out.b[0]); 

    const char* ip = ip_str;

    // if mixed-mode ip is found (ipv4 dot notation inside ipv6 then we will goto top here
    // however we only do this once, and if mixed is populated it will not return here to avoid infloop
    char* mixed = 0;

top:
    
    while (*ip == '[') ip++;

    if (sscanf(ip, "%hhu.%hhu.%hhu.%hhu", ip_int+12, ip_int+13, ip_int+14, ip_int+15) == 4)
    {
        ip_int[10] = 0xFFU;
        ip_int[11] = 0xFFU;
        for (int i = 0; i < 10; ++i)
            ip_int[i] = 0;
    }
    else if (mixed)
    {
        printl("failed to parse ipv6: `%s` into integer format (miexed)\n", ip_str);
        return std::nullopt;
    }
    else
    {


        char tmp[256]; tmp[0] = 0; tmp[1] = 0;
        strncpy(tmp, ip, sizeof(tmp));


        // find compression ::, if any
        char* compression = 0;
        for (char* x = tmp; *(x+1) != 0; ++x)
        if (*x == ':' && *(x+1) == ':')
        {
            *x = '\0';
            compression = x + 2;
            break;
        }

        uint16_t ip6_int[8];

        if (DEBUG && VERBOSE_DEBUG)
            printl("compression? %s - `%s`\n", (compression ? "yes" : "no"), (compression ? compression : ""));

        if (compression)
        {
            // compressed ipv6
            
            // first zero it out
            for (int i = 0; i < 8; ++i)
                ip6_int[i] = 0;

            int total_filled = 0;
        
            if (strcmp(ip, "::") == 0)
            {
                // do nothing in this special edge case, since we're already at all 0's
            }
            else
            {
                int upto = 0;
                char* pch = strtok(tmp, ":");
                
                while (pch != NULL)
                {
                    if (sscanf(pch, "%hx", &ip6_int[upto]) != 1)
                    {
                        printl("failed to parse ipv6: `%s` into integer format (compressed)\n", ip_str);
                        return std::nullopt;
                    }

                    total_filled++;
                    upto++;
                    if (upto >= 8)
                    {
                        printl("failed to parse ipv6: `%s` into integer format (compressed)\n", ip_str);
                        return std::nullopt;
                    }

                    pch = strtok(NULL, ":");
                }

                if (upto >= 8)
                {
                    printl("failed to parse ipv6: `%s` into integer format (compressed)\n", ip_str);
                    return std::nullopt;
                }

                upto = 0;

                if (*compression != 0)
                {
                    // check if it is a "mixed mode" ip. I.e. ipv4 dot notation inside ipv6
                    {
                        char* last_colon = compression;
                        for (char* x = compression; *x ; ++x)
                        if (*x == '.') //RH UPTO: here, detect and parse mixed mode correctly
                        {
                            mixed = last_colon + 1;
                            break;
                        }
                        else if (*x == ':')
                            last_colon = x;
                    }

                    if (mixed)
                    {
                        if (DEBUG && VERBOSE_DEBUG)
                            printl("mixed? %s\n", (mixed ? "yes" : "no"));
                        ip = mixed;
                        goto top;
                    }

                    uint16_t back6[16];
                    pch = strtok(compression, ":");
                    while (1)
                    {
                        if (sscanf(pch, (mixed ? "%u" : "%hx"), &back6[upto]) != 1)
                        {
                            printl("failed to parse ipv6: `%s` into integer format (compressed)\n", ip);
                            return std::nullopt;
                        }

                        total_filled++;
                        upto++;
                        
                        if (pch == NULL)
                            break;
                        
                        pch = strtok(NULL, ":");
                        
                        if (pch == NULL)
                            break;
                        
                        if (upto >= 8)
                        {
                            printl("failed to parse ipv6: `%s` into integer format (compressed)\n", ip);
                            return std::nullopt;
                        }
                    }

                    if (total_filled > 7)
                    {
                        printl("failed to parse ipv6: `%s` into integer format (compressed)\n", ip);
                        return std::nullopt;
                    }

                    for (int i = 0; i < upto; ++i)
                        ip6_int[8 - upto + i] = back6[i];
                }
            }
        }
        else
        {
            // full uncompressed ipv6
            if (sscanf(ip, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx", 
                    ip6_int + 0, ip6_int + 1, ip6_int + 2, ip6_int + 3,
                    ip6_int + 4, ip6_int + 5, ip6_int + 6, ip6_int + 7) != 8)
            {
                printl("failed to parse ipv6: `%s` into integer format (full uncompressed)\n", ip_str);
                return std::nullopt;
            }
        }

        for (int i = 0; i < 8; ++i)
        {
            ip_int[i*2 + 0] = (uint8_t)(ip6_int[i] >> 8U);
            ip_int[i*2 + 1] = (uint8_t)(ip6_int[i] & 0xFFU);
        }
    }
    return {out};
}

// if the ipv6 address in ip is actually an ipv4 address then return it in normal dot notation form
std::string str_ip(uint8_t* ip)
{
    uint8_t* ip_int = ip;
    char ip_buf[64];

    // procecess ipv4 in ipv6 addresses as ipv4
    if (ip_int[0] == 0 && ip_int[1] == 0 && ip_int[2] == 0 && ip_int[3] == 0 &&
        ip_int[4] == 0 && ip_int[5] == 0 && ip_int[6] == 0 && ip_int[7] == 0 &&
        ip_int[8] == 0 && ip_int[9] == 0 && ip_int[10] == 0xFFU && ip_int[11] == 0xFFU)
    {
        snprintf(ip_buf, sizeof(ip_buf) - 1, "%u.%u.%u.%u", ip_int[12], ip_int[13], ip_int[14], ip_int[15]);
        return ip_buf;
    }
    else
    {
        snprintf(ip_buf, sizeof(ip_buf) - 1,
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            COPY16(ip_int));
        return ip_buf;
    }
}

std::string str_ip(IP const& ip)
{
    return str_ip((uint8_t*)(ip.b));
}

std::optional<std::pair<IP, int>> parse_endpoint(const char* str, int len)
{
    char tmp[256];
    strncpy(tmp, str, sizeof(tmp)-1);
    tmp[255] = 0;

    // find port
    char* port = tmp + strlen(tmp) - 1;
    while (port != tmp && *port != ':')
        port--;
    *port++ = 0;

    // try parse port first
    uint32_t port_int = 0;
    if (sscanf(port, "%u", &port_int) != 1)
    {
        if (DEBUG)
            printl("could not parse port when parsing endpoint: `%s`\n", str);
        return std::nullopt;
    }

    // now try parse ip
    std::optional<IP> parse_ip = canonicalize_ip(tmp);
    if (!parse_ip)
    {
        if (DEBUG)
            printl("could not parse ip when parsing endpoint: `%s`\n", str);
        return std::nullopt;
    }

    return {{*parse_ip, port_int}};
}
