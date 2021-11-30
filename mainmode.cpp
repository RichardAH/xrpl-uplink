#include "uplink.h"

#define ACCEPT_QUEUE 10
// ---------
// MAIN MODE
// ---------

inline pid_t my_pid;

int main_mode(
        char* ip, int port, int peer_max,
        char* peer_path, char* subscriber_path, char* db_path, uint8_t* key,
        ddmode dd_default, std::map<uint8_t, ddmode>& dd_specific)
{

    my_pid = getpid();

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
        }

        // process incoming messages
        uint8_t message_header[128];
        for (int i = 2; i < MAX_FDS; ++i)
        {
            if (fdset[i].fd >= 0 && fdset[i].revents & POLLIN)
            {

                struct msghdr header;
                ssize_t rc = recvmsg(fdset[i].fd, &header, MSG_PEEK);

                if (rc <= 0)
                {
                    // disconnect peer
                    // set fd negative
                    // remove from set if applicable
                    continue;
                }

                // process MessageUnknown

            }
        }
    }
    return 0;
}


