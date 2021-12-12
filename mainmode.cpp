#include "uplink.h"

#define ACCEPT_QUEUE 10
// ---------
// MAIN MODE
// ---------


int main_mode(
        char* ip, int port, int peer_max,
        char* peer_path, char* subscriber_path, char* db_path, uint8_t* key,
        ddmode dd_default, std::map<uint8_t, ddmode>& dd_specific, int rnd_fd)
{

    my_pid = getpid();

    std::map<Hash, uint32_t, HashComparator> global_seen_p2s; // distinct from per peer seen_p2s

    uint8_t* packet_buffer =
        (uint8_t*)(malloc(PACKET_BUFFER_NORM));

    size_t packet_buffer_len = PACKET_BUFFER_NORM;

    if (!packet_buffer)
    {
        printl("Malloc failed while creating packet_buffer\n");
        return EC_BUFFER;
    }


    // task 1: open /var/run/xrpl-uplink/peer.sock accept mode
    int peer_accept = -1;
    {

        printl("peer socket: %s\n", peer_path);

        if ((peer_accept = create_unix_accept(peer_path)) < 0)
        {
            printl("Could not create peer accept socket\n");
            return -peer_accept;
        }

        if (!fd_set_flags(peer_accept, O_CLOEXEC | O_NONBLOCK))
        {
            printl("Could not set flags\n");
            return EC_UNIX;
        }

        if (listen(peer_accept, ACCEPT_QUEUE) == -1)
        {
            printl("Could not call listen on peer_accept unix domain socket\n");
            return EC_UNIX;
        } 
    }


    // task 2: open /var/run/xrpl-uplink/subscriber.sock accept mode
    int subscriber_accept = -1;
    {
        printl("subscriber socket: %s\n", subscriber_path);

        if ((subscriber_accept = create_unix_accept(subscriber_path)) < 0)
        {
            printl("Could not create subscriber accept socket\n");
            return -subscriber_accept;
        }

        if (!fd_set_flags(subscriber_accept, O_CLOEXEC | O_NONBLOCK))
        {
            printl("Could not set flags\n");
            return EC_UNIX;
        }

        if (listen(subscriber_accept, ACCEPT_QUEUE) == -1)
        {
            printl("Could not call listen on subscriber_accept unix domain socket\n");
            return EC_UNIX;
        } 
    }


    // task 3: poll loop on connected/ing peers and connected/ing subscribers
    struct pollfd fdset[MAX_FDS];
    // clear fd structure
    for (int i = 0; i < MAX_FDS; ++i)
    {
        fdset[i].fd = -1;
        fdset[i].events = 0;
    }

    // preload our listening fds
    fdset[0].fd = peer_accept;
    fdset[0].events = POLLIN;
    fdset[1].fd = subscriber_accept;
    fdset[1].events = POLLIN;

    std::set<int> subscribers;
    while (1)
    {

        int poll_result = poll(fdset, MAX_FDS, -1);
        if (poll_result == -1)
        {
            printl("Poll returned -1. Errno=%d\n", errno);
            return 5;
        }

        if (((fdset[0].revents & POLLERR) ||
                    (fdset[0].revents & POLLHUP) ||
                    (fdset[0].revents & POLLNVAL)) &&
                ((fdset[1].revents & POLLERR) ||
                 (fdset[1].revents & POLLHUP) ||
                 (fdset[1].revents & POLLNVAL)))
        {
            printl("Accept socket error or hangup.\n");
            break;
        }

        //printl("poll result %d\n", poll_result);

        // process accepts
        if (fdset[0].revents & POLLIN || fdset[1].revents & POLLIN)
        {
            int new_fd = -1;
            int is_subscriber = 0;
            while ( 
                    ((new_fd = accept(peer_accept, NULL, NULL)) > -1) ||
                    ((new_fd = accept(subscriber_accept, NULL, NULL)) > -1 && (is_subscriber = 1)))
            {

                // make new fd non-blocking
                fd_set_flags(new_fd, O_NONBLOCK);

                // insert
                printl("Accepting connection fd=%d\n", new_fd);
                int found = -1;
                for (int i = 0; i < MAX_FDS; ++i)
                    if (fdset[i].fd < 0)
                    {
                        fdset[i].fd = new_fd;
                        fdset[i].events = POLLIN;
                        found = i;
                        break;
                    }


                if (found == -1)
                {
                    printl("Could not accept incoming unix domain peer.sock connection (fds full)\n");
                    close(new_fd);
                }
                else if (is_subscriber)
                {
                    subscribers.emplace(new_fd);
                    is_subscriber = 0;
                }
                else    // peer-mode connecting in, send dd info
                {
                    Message m;
                    memset(&m, 0, sizeof(Message));
                    m.ddmode.flags = 1U << 28U;

                    // default is the first entry, high byte is 0
                    m.ddmode.mode[0] = dd_default;

                    int i = 0;
                    for (auto const& e: dd_specific)
                        m.ddmode.mode[i++] = (((uint16_t)e.first) << 8U) | ((uint16_t)e.second);

                    if (write(new_fd, (void*)(&m), sizeof(Message)) == -1)
                    {
                        printl("failed to send ddmode message to newly accepted peer-mode client\n");
                        close(new_fd);
                    }
                }
            }
        } // accepts

        // process incoming messages from peers to subscribers
        uint8_t message_header[128];
        for (int i = 2; i < MAX_FDS; ++i)
        {
            if (fdset[i].fd >= 0 && fdset[i].revents & POLLIN)
            {
                int fd = fdset[i].fd;
                bool is_subscriber = subscribers.find(fdset[i].fd) != subscribers.end();

                ssize_t rc = recv(fdset[i].fd, message_header, sizeof(message_header), MSG_PEEK);
                if (rc <= 0)
                {
                    // disconnect peer
                    close(fd);

                    // remove from set if applicable
                    if (is_subscriber)
                        subscribers.erase(fd);

                    // set fd negative
                    fdset[i].fd = -1;
                    continue;
                }


                if (is_subscriber)
                {
                    // incoming message from subscriber to peers
                }
                else
                {

                    // incoming message from peer to subscribers
                    Message* m = (Message*)((void*)message_header);
                    int mtype = m->unknown.flags >> 28U;
                    if (mtype == 0)
                    {

                        char ip[40]; ip[0] ='\0';

                        char* x = ip;
                        for (int j = 0; j < 16; ++j)
                        {
                            int hi = (m->packet.source_addr[j] >> 4U);
                            int lo = (m->packet.source_addr[j] & 0xFU);
                            *x++ = (hi > 9 ? (hi - 10) + 'A' : hi + '0');
                            *x++ = (lo > 9 ? (lo - 10) + 'A' : lo + '0');
                            if (i % 2 == 1)
                                *x++ = ':';
                        }
                        *x = '\0';


                        if (DEBUG)
                            printl("packet: %d size: %d ip: %s port: %d\n", 
                                m->packet.type, m->packet.size, ip, m->packet.source_port);

                        uint32_t packet_expected = sizeof(MessagePacket) + m->packet.size;

                        // todo: process mtENDPOINTS, construct new peers

                        uint16_t& packet_type = m->packet.type;
                        Hash* packet_hash = reinterpret_cast<Hash*>(m->packet.hash);


                        // check dd rules
                        {
                            ddmode d = dd_default;
                            if (d == DD_NOT_SET)
                                d = DD_ALL;

                            // ping and endpoints are default drop
                            if (packet_type == mtPING || packet_type == mtENDPOINTS)
                                d = DD_DROP;

                            // however if the user specifically set mtPING: then we will forward
                            if (dd_specific.find(packet_type) != dd_specific.end())
                                d = dd_specific[packet_type];

                            bool drop  =    d == DD_BLACKHOLE   || d == DD_DROP     || d == DD_DROP_N;
                            bool dedup =    d == DD_ALL         || d == DD_PEER     || d == DD_SQUELCH;

                            if (dedup && global_seen_p2s.find(*packet_hash) != global_seen_p2s.end())
                                drop = true;

                            if (DEBUG && drop)
                                printl("dropping packet %d due to dd\n", packet_type);
                                
                            // upgrade to a larger buffer if needed
                            ASSERT(resize_buffer(&packet_buffer, packet_expected, &packet_buffer_len,
                                PACKET_BUFFER_NORM, PACKET_BUFFER_MAX));

                            // read packet
                            if (!drop || packet_type == mtENDPOINTS)
                            {
                                if (recv(fdset[i].fd, packet_buffer, packet_expected, 0) != packet_expected)
                                    printl("error reading packet from peer process\n");
                            }
                            else
                            {
                                recv(fdset[i].fd, 0, 0, 0); // null read
                                continue;
                            }

                            if (!drop)
                            {

                                if (dedup)
                                {
                                    global_seen_p2s.emplace(*packet_hash, time(NULL));
                                    random_eviction(global_seen_p2s, rnd_fd, EVICTION_SPINS);
                                }


                                if (DEBUG)
                                    printl("sending packet to %ld subscribers\n", subscribers.size());

                                for (int sub_fd : subscribers)
                                    write(sub_fd, packet_buffer, packet_expected);
                            }
                        }

                        if (packet_type == mtENDPOINTS)
                        {
                            std::vector<std::pair<std::string, int>> ips;
                            int c = parse_endpoints(
                                    packet_buffer + sizeof(Message), packet_expected - sizeof(Message), ips);
                            printl("parse_endpoints = %d\n", c);
                            for (auto& p : ips)
                                printl("endpoint: %s : %d\n", p.first.c_str(), p.second);

                            // RH UPTO: connect to and store endpoint peers
                            // RH TODO: collect endpoints from 503s
                        }
                    }
                }
            }
        }

    }
    return 0;
}


