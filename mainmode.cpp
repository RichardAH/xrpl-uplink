#include "uplink.h"


// ---------
// MAIN MODE
// ---------

int main_mode(char* ip, int port, int peer_max, char* sock_path, char* db_path)
{
    // task 1: open /var/run/xrpl-uplink/peer.sock accept mode
    int peer_accept = -1;
    {
    
        char path[PATH_MAX];
        if (snprintf(path, PATH_MAX, "%s/%s", sock_path, PEER_FN) < 0)
        {
            fprintf(stderr, "Could not evaluate peer socket path\n");
            return 1;
        }

        printf("Peer socket: %s\n", path);

        if ((peer_accept = create_unix_accept(path)) == -1)
        {
            fprintf(stderr, "Could not create peer accept socket\n");
            return 1;
        }

        if (!fd_set_flags(peer_accept, O_CLOEXEC | O_NONBLOCK))
            return 2;
    }


    // task 2: open /var/run/xrpl-uplink/subscriber.sock accept mode
    int subscriber_accept = -1;
    {
        char path[PATH_MAX];
        if (snprintf(path, PATH_MAX, "%s/%s", sock_path, SUBSCRIBER_FN) < 0)
        {
            fprintf(stderr, "Could not evaluate subscriber socket path\n");
            return 1;
        }

        printf("Subscriber socket: %s\n", path);

        if ((subscriber_accept = create_unix_accept(path)) == -1)
        {
            fprintf(stderr, "Could not create subscriber accept socket\n");
            return 1;
        }

        if (!fd_set_flags(subscriber_accept, O_CLOEXEC | O_NONBLOCK))
            return 2;

    }


    // task 3: poll loop on connected/ing peers and connected/ing subscribers
    struct pollfd fds[MAX_FDS];
    // clear fd structure
    for (int i = 0; i < MAX_FDS; ++i)
    {
        fds[i].fd = -1;
        fds[i].events = 0;
    }

    // preload our listening fds
    fds[0].fd = peer_accept;
    fds[0].events = POLLIN;
    fds[1].fd = subscriber_accept;
    fds[1].events = POLLIN;

    while (1)
    {

        int poll_result = poll(fds, MAX_FDS, -1);
        if (poll_result == -1)
        {
            fprintf(stderr, "Poll returned -1. Errno=%d\n", errno);
            return 5;
        }

        printf("poll result %d\n");

        sleep(1);
    }
    return 0;
}


