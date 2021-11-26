#define VERSION             "0.1"
#define DEFAULT_SOCK_PATH   "/var/run/xrpl-uplink"
#define DEFAULT_DB_PATH     "/var/lib/xrpl-uplink"
#define PEER_FN             "peer.sock"
#define SUBSCRIBER_FN       "subscriber.sock"
#define DB_FN               "peer.db"
#define KEY_FN              "peer.key"
#define USER_AGENT          "xrpl-uplink"
#define MAX_FDS 1024
#include <stdio.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
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
#include <nmmintrin.h>
#include <sodium.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "sha-256.h"
#include "libbase58.h"


typedef union hash_ {
    uint8_t b[32];
    uint32_t d[8];
    uint64_t q[4];
} Hash;

enum ddmode : int8_t 
{
    DD_INVALID = -1,
    DD_ALL = 0,
    DD_NONE = 1,
    DD_SUB = 2,
    DD_PEER = 3
};

enum ercode : int
{
    EC_SUCCESS      = 0,    // not an error, normal status
    EC_GENERIC      = 1,    // a sanity check failed
    EC_PARAMS       = 2,    // there was a problem with the params passed on cmdline
    EC_TCP          = 3,    // there was a tcp socket issue (creating, connecting)
    EC_UNIX         = 4,    // there was a unix sock  issue (creating, connecting)
    EC_SPAWN        = 5,    // could not fork exec
    EC_SSL          = 6,    // there was a problem with an openssl routine
    EC_POLL         = 7,    // poll returned abnormally
    EC_SODIUM       = 8,    // problem loading or calling libsodium
    EC_SECP256K1    = 9,    // problem with a libsecp256k1 call
    EC_BUFFER      = 10,    // internal buffer was insufficiently large for an operation
    EC_ADDR        = 11     // invalid address or hostname specified / could not resolve

};

int fd_set_flags(int fd, int new_flags);
int create_unix_accept(char* path);
int32_t packet_id(char* packet_name);

int peer_mode(
    char* ip, int port, char* main_path, uint8_t* key, 
    ddmode dd_default, std::map<int32_t, ddmode>& dd_specific);

int main_mode(
    char* ip, int port, int peer_max,
    char* peer_path, char* subscriber_path, char* db_path, uint8_t* key,
    ddmode dd_default, std::map<int32_t, ddmode>& dd_specific);

Hash hash(const void* mem, int len);
