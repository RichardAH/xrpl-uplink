#define VERSION             "0.1"
#define DEFAULT_SOCK_PATH   "/var/run/xrpl-uplink"
#define DEFAULT_DB_PATH     "/var/lib/xrpl-uplink"
#define PEER_FN             "peer.sock"
#define SUBSCRIBER_FN       "subscriber.sock"
#define DB_FN               "peers.db"
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
#include <cstdlib>
#include <stdint.h>
#include <map>
enum ddmode : int8_t 
{
    DD_INVALID = -1,
    DD_ALL = 0,
    DD_NONE = 1,
    DD_SUB = 2,
    DD_PEER = 3
};

int fd_set_flags(int fd, int new_flags);
int create_unix_accept(char* path);
int32_t packet_id(char* packet_name);
int main_mode(char* ip, int port, int peer_max, char* sock_path, char* db_path);
int peer_mode(char* ip, int port, char* sock_path);
