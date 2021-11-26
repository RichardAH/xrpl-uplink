#include "uplink.h"


// ---------
// MAIN MODE
// ---------

inline pid_t my_pid;

int main_mode(
        char* ip, int port, int peer_max,
        char* peer_path, char* subscriber_path, char* db_path, uint8_t* key,
        ddmode dd_default, std::map<int32_t, ddmode>& dd_specific)
{

    my_pid = getpid();

    // task 1: open /var/run/xrpl-uplink/peer.sock accept mode
    int peer_accept = -1;
    {
    
        printf("Peer socket: %s\n", peer_path);

        if ((peer_accept = create_unix_accept(peer_path)) < 0)
        {
            fprintf(stderr, "[%s:%d pid=%d] Could not create peer accept socket\n",
                __FILE__, __LINE__, my_pid);
            return -peer_accept;
        }

        if (!fd_set_flags(peer_accept, O_CLOEXEC | O_NONBLOCK))
        {
            fprintf(stderr, "[%s:%d pid=%d] Could not set flags\n",
                __FILE__, __LINE__, my_pid);
            return EC_UNIX;
        }
        
        // todo: listen() call here
    }


    // task 2: open /var/run/xrpl-uplink/subscriber.sock accept mode
    int subscriber_accept = -1;
    {
        printf("Subscriber socket: %s\n", subscriber_path);

        if ((subscriber_accept = create_unix_accept(subscriber_path)) < 0)
        {
            fprintf(stderr, "Could not create subscriber accept socket\n");
            return -subscriber_accept;
        }

        if (!fd_set_flags(subscriber_accept, O_CLOEXEC | O_NONBLOCK))
        {
            fprintf(stderr, "[%s:%d pid=%d] Could not set flags\n",
                __FILE__, __LINE__, my_pid);
            return EC_UNIX;
        }

        // todo: listen() call here

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
            fprintf(stderr, "Poll returned -1. Errno=%d\n", errno);
            return 5;
        }

        printf("poll result %d\n", poll_result);

        // process accepts
        if (fdset[0].revents & POLLIN || fdset[1].revents & POLLIN)
        {
            int new_fd = -1;
            int is_subscriber = 0;
            while ( 
                ((new_fd = accept(peer_accept, NULL, NULL)) > -1) ||
                ((new_fd = accept(subscriber_accept, NULL, NULL)) > -1 && (is_subscriber = 1)))
            {
                // insert
                fprintf(stderr, "[%s:%d pid=%d] Accepting connection fd=%d\n",
                        __FILE__, __LINE__, my_pid, new_fd);
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
                    fprintf(stderr,
                            "[%s:%d pid=%d] Could not accept incoming unix domain peer.sock connection (fds full)\n",
                            __FILE__, __LINE__, my_pid);
                    close(new_fd);
                }
                else if (is_subscriber)
                {
                    subscribers.emplace(new_fd);
                    is_subscriber = 0;
                }
            }
        }

        // process incoming messages
        //


        sleep(1);
    }
    return 0;
}


