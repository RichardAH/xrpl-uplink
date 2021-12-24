#include "uplink.h"

#define ACCEPT_QUEUE 10
// ---------
// MAIN MODE
// ---------

int prng (int i)
{
    return std::rand() % i;
}

int main_mode(
        IP* ip, int* port, int peer_max,
        char* peer_path, char* subscriber_path, char* db_path, uint8_t* key,
        ddmode dd_default, std::map<uint8_t, ddmode>& dd_specific, int rnd_fd)
{


    uint64_t random_words[32];
    if (read(rnd_fd, random_words, sizeof(random_words)) != sizeof(random_words))
    {
        printl("Could not read /dev/random\n");
        return EC_RNG;
    }

    std::srand(random_words[0] ^ time(NULL));

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

    std::set<int> subscribers; // fd
    
    std::map<int, std::pair<IP, int>> peers;     // fd -> {ip, port}
    std::map<int, PubKey> peers_key;             // fd -> pubkey
    std::map<std::pair<IP, int>, int, IPComparator> peers_rev; // {ip, port} -> fd

    std::map<int, uint64_t> subscribers_counter; // fd -> counter | counts which peer we are up to in a round robin

    while (1)
    {

        // reap any zombies we have
        {
            int status;
            waitpid(-1, &status, WNOHANG);
        }

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
                fd_set_flags(new_fd, O_NONBLOCK | O_CLOEXEC);


                // reject if full
                if (!is_subscriber && peers.size() > peer_max)
                {
                    printl("rejecting incoming peermode connection due to peer_max\n");
                    close(new_fd);
                    continue;
                }

                // insert
                if (DEBUG)
                    printl("new peer-mode uplink connected in fd=%d\n", new_fd);
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
                    subscribers_counter[new_fd] = 0;
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
                    {
                        printl("subscriber disconnected\n");
                        subscribers.erase(fd);
                        subscribers_counter.erase(fd);

                    }
                    else if (peers.find(fd) != peers.end())
                    {
                        std::string peer_ip = str_ip(peers[fd].first);
                        printl("peermode disconnected %s:%d\n",
                            peer_ip.c_str(), peers[fd].second);

                        int peer_port = peers[fd].second;

                        peers_rev.erase(peers[fd]);
                        peers.erase(fd);
                        peers_key.erase(fd);

                        if (peer_ip == str_ip(*ip) && peer_port == *port)
                        {
                            // our core / first ip disconnected
                            // so lets try reconnect it
                            if (fork() == 0)
                                return EC_BECOME_PEER;
                        } 
                    }

                    // set fd negative
                    fdset[i].fd = -1;
                    continue;
                }


                if (is_subscriber)
                {
                    // incoming message from subscriber to peers
                    
                    // RH TODO: manage this buffer properly

                    uint8_t buffer_in[1048576];

                    size_t bytes_read = recv(fdset[i].fd, buffer_in, sizeof(buffer_in), 0);

                    if (bytes_read == 1048576)
                    {
                        printl("skipping large subscriber packet > 1048576\n");
                    }
                    else
                    {
//                        if (DEBUG)

                        Message* m = reinterpret_cast<Message*>(buffer_in);
                        int mtype = m->unknown.flags >> 28U;
                        
                        printl("incoming message from subscriber: %ld bytes, mtype=%d\n", bytes_read, mtype);

                        if (mtype == M_PACKET)
                        {
                            int opcode = (m->unknown.flags >> 16U) & 0xFFU;

                            printl("opcode: %d\n", opcode);

                            switch (opcode)
                            {
                                case R_ALL:
                                {
                                    for (auto& p: peers)
                                    {
                                        if (DEBUG)
                                            printl("sending all: fd=%d\n", p.first);
                                        write(p.first, buffer_in, bytes_read);
                                    }

                                    break;
                                }

                                case R_MASK:
                                {
                                    uint8_t mask = m->unknown.flags & 0xFFU;

                                    uint8_t byte_match = mask / 8U;
                                    uint8_t bit_match = mask & 8U;

                                    for (auto& p: peers)
                                    {
                                        if (peers_key.find(p.first) == peers_key.end())
                                            continue;

                                        if (memcmp(
                                                reinterpret_cast<const void*>(&(peers_key[p.first].b)),
                                                reinterpret_cast<const void*>(&(m->packet.destination_peer)),
                                                byte_match) == 0)
                                        {
                                            if (bit_match > 0)
                                            {
                                                uint8_t a = peers_key[p.first].b[byte_match];
                                                uint8_t b = m->packet.destination_peer[byte_match];
                                                uint8_t bitmask = 0xFFU;        // all 1s
                                                bitmask >>= (8U - bit_match);   // erase some bits on the rhs
                                                bitmask <<= (8U - bit_match);
                                                if ((a & bitmask) == (b & bitmask))
                                                {
                                                    // mask matches
                                                    if (DEBUG)
                                                        printh(peers_key[p.first].b, 32, "sending bitmask: ");
                                                    write(p.first, buffer_in, bytes_read);
                                                }
                                            }
                                        }
                                    }

                                    break;
                                }
                                
                                case R_RANDOM:
                                {
                                    int count = m->packet.flags & 0xFFFFU;
                                    printl("R_RANDOM: count=%d\n", count);
                                    if (count >= peers.size())
                                    {
                                        int i = 0;
                                        for (auto& p: peers)
                                        {
                                            printl("sending random: fd=%d [%d/%d]\n",
                                                    p.first, i++, count);
                                            write(p.first, buffer_in, bytes_read);
                                        }
                                    }
                                    else
                                    {
                                        std::vector<int> fds;
                                        for (auto& p: peers)
                                            fds.push_back(p.first);

                                        std::random_shuffle(fds.begin(), fds.end());
                                        
                                        for (int i = 0; i < count; ++i)
                                        {
                                            printl("sending random: fd=%d [%d/%d]\n",
                                                    fds[i], i, count);
                                            write(fds[i], buffer_in, bytes_read);
                                        }
                                    }
                                    break;
                                }

                                case R_ROBIN:
                                {

                                    int count = m->packet.flags & 0xFFFFU;

                                    uint64_t upto = (subscribers_counter[fdset[i].fd] >> 10U) % peers.size();

                                    for (auto& p: peers)
                                    {
                                        if (upto-- == 0)
                                        {
                                            if (DEBUG)
                                                printl("sending round robin: fd=%d, count=%lu\n",
                                                    p.first, subscribers_counter[fdset[i].fd]);

                                            write(p.first, buffer_in, bytes_read);
                                            break;
                                        }
                                    }
                                    subscribers_counter[fdset[i].fd] += count;
                                    break;
                                }
                            }
                        }
                    }
                }
                else
                {

                    // incoming message from peer to subscribers
                    Message* m = (Message*)((void*)message_header);
                    int mtype = m->unknown.flags >> 28U;

                    if (mtype == 2) // MessagePeerStatus
                    {

                        std::string ip_str = str_ip(m->status.remote_addr);

                        IP ip = { 
                            .b = { COPY16(m->status.remote_addr) }
                        };

                        recv(fdset[i].fd, 0, 0, 0); // null read
                        // reject if full
                        if (peers.size() >= peer_max)
                        {
                            close(fdset[i].fd);
                            fdset[i].fd = -1;

                            printl("dropping peer due to max_peer limit: %s:%d\n", 
                                    ip_str.c_str(), m->packet.source_port);
                        }
                        else
                        {
                            peers_rev[{ip, m->packet.source_port}] = fdset[i].fd;
                            peers[fdset[i].fd] = {ip, m->packet.source_port};
                            peers_key.emplace(std::make_pair(fdset[i].fd, 
                                        PubKey{ .b = {COPY32(m->status.remote_peer)} }));
                            printl("peer added: [%s]:%d\n", ip_str.c_str(), m->packet.source_port);
                        }
                    }
                    else if (mtype == 0)
                    {

                        if (DEBUG)
                        {
                            std::string ip = str_ip(m->packet.source_addr);
                            printl("packet: %d size: %d ip: %s port: %d\n", 
                                m->packet.type, m->packet.size, ip.c_str(), m->packet.source_port);
                        }

                        uint32_t packet_expected = sizeof(MessagePacket) + m->packet.size;

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
                            std::vector<std::pair<IP, int>> endpoints;
                            int c = parse_endpoints(
                                    packet_buffer + sizeof(Message), packet_expected - sizeof(Message), endpoints);
                            //printl("parse_endpoints = %d\n", c);
                            int counter = peer_max - peers.size();
                            if (counter > 0)
                            {
                                printl("trying to spawn %d peers\n", counter);
                                for (auto& p : endpoints)
                                {
                                    if (counter-- <= 0)
                                        break;
                                    // we're going to fork, then return in the fork to uplink.cpp
                                    // whilst asking it to turn us into a peer
                                    if (fork() == 0)
                                    {
                                        *ip = p.first;
                                        *port = p.second;
                                        return EC_BECOME_PEER;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return EC_SUCCESS;
}


