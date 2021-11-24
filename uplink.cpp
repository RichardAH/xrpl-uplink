#define VERSION             "0.1"
#define SOCK_PATH           "/var/run/xrpl-uplink"
#define PEER_FN             "peer.sock"
#define SUBSCRIBER_FN       "subscriber.sock"
#define MAX_FDS 1024
#include <stdio.h>
#include <sys/socket.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

int print_usage(int argc, char** argv, const char* error)
{
    fprintf(stderr, 
            "XRPL-Uplink v%s by Richard Holland / XRPL-Labs\n%s%s"
            "Usage: %s <max-peers> <peer-ip> <peer-port>    - run as main process\n"
            "       %s connect <peer-ip> <peer-port>        - run as peer process\n",
            VERSION, (error ? error : ""), (error ? "\n" : ""), argv[0], argv[0]); 

    return 1;
}

// configure an fd to be nonblocking and close on exec
int fd_set_flags(int fd, int new_flags)
{
    int existing_flags = fcntl(fd, F_GETFL);
    if (existing_flags == -1)
    {
        fprintf(stderr, "Could not get fd flags: %d\n", errno);
        return 0;
    }
    if (fcntl(fd, F_SETFL, existing_flags | new_flags) == -1)
    {
        fprintf(stderr, "Could not set fd flags: %d\n", errno);
        return 0;
    }
    return 1;
}

int create_unix_accept(char* path)
{
    int fd = -1;
    struct sockaddr_un server_sockaddr;
    memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
    if ((fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) == -1)
    {
        fprintf(stderr, "Could not create unix domain socket: %d\n", errno);
        return -1;
    }
  
    server_sockaddr.sun_family = AF_UNIX;   
    strcpy(server_sockaddr.sun_path, path); 
    size_t len = sizeof(server_sockaddr);
    unlink(path);

    if (bind(fd, (struct sockaddr *) &server_sockaddr, len) == -1)
    {
        fprintf(stderr, "Could not bind to unix domain socket: %d\n", errno);
        return -1;
    }

    return fd;
}


// ---------
// MAIN MODE
// ---------

int main_mode(char* ip, int port, int peer_max)
{
    // task 1: open /var/run/xrpl-uplink/peer.sock accept mode
    int peer_accept = -1;
    {
    
        char path[PATH_MAX];
        if (snprintf(path, PATH_MAX, "%s/%s", SOCK_PATH, PEER_FN) < 0)
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
        if (snprintf(path, PATH_MAX, "%s/%s", SOCK_PATH, SUBSCRIBER_FN) < 0)
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


// ---------
// PEER MODE
// ---------
int peer_mode(char* ip, int port)
{

    while(1)
    {
        sleep(1);
    }
    return 0;
}



int main(int argc, char** argv)
{
    if (!(mkdir(SOCK_PATH, 0700) == 0 || errno == EEXIST))
    {
        fprintf(stderr, "Could not create directory: `%s` for socket files\n", SOCK_PATH);
        return 1;
    }
    
    if (argc != 4)
    {
        print_usage(argc, argv, 0);
        return 1;
    }

    char* ip = argv[2];
    int port = 0;
    if (sscanf(argv[3], "%d", &port) != 1 || port < 1 || port > 65525)
    {
        print_usage(argc, argv, "port must be a number between 1 and 65535 inclusive");
        return 1;
    }

    int peer_max = 0;

    if (strlen(argv[1]) == 7 && memcmp(argv[1], "connect", 7) == 0)
    {
        // peer mode
        return peer_mode(ip, port);
    }
    else if (sscanf(argv[1], "%d", &peer_max) == 1 && peer_max > 1)
    {
        // main mode

        // spawn first peer before continuing to main mode
        if (fork() == 0)
        {
            // all our FDs are close on exec
            execlp(argv[0], argv[0], "connect", argv[2], argv[3], (char*)0);
            // should be unreachable
            fprintf(stderr, "Execlp failed, could not spawn peer process\n");
            return 10;
        }

        // continue to main mode
        return main_mode(ip, port, peer_max);
    }
    else
    {
        print_usage(argc, argv, "max-peers must be at least 1");
        return 1;
    }

}

