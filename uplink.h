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
#include <set>
#include <nmmintrin.h>
#include <sodium.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "sha-256.h"
#include "libbase58.h"
#include "ripple.pb.h"
#include <time.h>
#include <sys/uio.h>

#define printl(s, ...)\
    fprintf(stderr, "%lu [%s:%d pid=%d] " s, time(NULL), __FILE__, __LINE__, my_pid, ##__VA_ARGS__)

#define COPY32(x)  x[0],x[1],x[2],x[3],x[4],x[5],x[6],x[7],x[8],x[9],x[10],x[11],x[12],x[13],x[14],x[15],\
    x[16],x[17],x[18],x[19],x[20],x[21],x[22],x[23],x[24],x[25],x[26],x[27],x[28],x[29],x[30],x[31]

#define FORMAT32 "%02X%02X%02X%02X %02X%02X%02X%02X  %02X%02X%02X%02X %02X%02X%02X%02X "\
                 "%02X%02X%02X%02X %02X%02X%02X%02X  %02X%02X%02X%02X %02X%02X%02X%02X "
typedef union hash_
{
    uint8_t b[32];
    uint32_t d[8];
    uint64_t q[4];
} Hash;

struct HashComparator
{
    bool operator()(const Hash& lhs, const Hash& rhs) const
    {
        return memcmp(&lhs, &rhs, 32) < 0;
    }
};


// All unix-domain piped messages are prefixed with a 128 byte header. The minimum size of a message is 128 bytes.


enum MessageType : uint8_t
{
    M_PACKET = 0,
    M_DDMODE = 1,
    M_PEERSTATUS = 2
};

/**
 * Packet header is attached to all messages containing a packet in either direction
 */
struct MessagePacket
{
    uint32_t flags;             // (flags >> 28U) == 0
    uint32_t size;
    uint32_t timestamp;
    uint16_t type;
    uint16_t source_port;
    uint8_t  source_addr[16];
    uint8_t  hash[32];
    uint8_t  source_peer[32];
    uint8_t  destination_peer[32];
};

struct MessageDDMode
{
    uint32_t flags;         // (flags >> 28U) == 1
    uint16_t mode[62];     // [<packet_type (uint8_t), dd_mode (uint8_t)> (uint16_t)]*
};

struct MessagePeerStatus
{
    uint32_t flags;             // (flags >> 28U) == 2
    uint32_t reserved1;
    uint32_t timestamp;
    uint16_t type;              // 0 = connected, 1 = disconnected
    uint16_t destination_port;
    uint8_t  destination_addr[16];
    uint8_t reserved2[32];
    uint8_t local_peer[32];     // our key
    uint8_t remote_peer[32];    // their key
};

struct MessageUnknown           // used when ascertaining the message type
{
    uint32_t flags;
    uint8_t data[124];
};

union Message
{
    MessagePacket packet;
    MessageDDMode ddmode;
    MessagePeerStatus peer;
    MessageUnknown unknown;
};



/**
 * N = not de-duplicated
 * D = de-duplicated
 * B = dropped/destroyed
 
 Peer   Subscriber      ddmode
    D            D      DD_ALL
    D            N      DD_PEER
    D            B      DD_SQUELCH
    N            D      DD_SUB
    N            N      DD_NONE
    N            B      DD_SQUELCH_N
    B            D      DD_DROP
    B            N      DD_DROP_N
    B            B      DD_BLACKHOLE
*/


enum ddmode : uint8_t 
{
    DD_NOT_SET   =   255,  // placeholder indicating a dd mode was not specified
    DD_INVALID   =   0,
    DD_ALL       =   1,   // de-duplicate packets in both directions
    DD_NONE      =   2,   // do not de-duplicate packets in either direction
    DD_SUB       =   3,   // de-duplicate packets routed from subscribers to peers (but not peers to subscribers)
    DD_PEER      =   4,   // de-duplicate packets routed from peers to subscribers (but not subscribers to peers)
    DD_DROP      =   5,   // drop packets routed from peers to subscribers
                          // and de-duplicate packets from subscribers to peers
    DD_DROP_N    =   6,   // drop packets routed from peers to subscribrs
                          // do NOT de-duplicate packet from subscribers to peers
    DD_BLACKHOLE =   7,   // drop packets in both directions
    DD_SQUELCH   =   8,   // drop subscriber's packets, de-duplicate peer's packets
    DD_SQUELCH_N =   9    // drop subscriber's packets, do NOT de-duplicate peer's packets
};

ddmode parse_dd(char* dd);

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
    EC_ADDR        = 11,    // invalid address or hostname specified / could not resolve
    EC_PROTO       = 12     // something illegal according to xrpl protocol rules happened

};

int fd_set_flags(int fd, int new_flags);
int create_unix_accept(char* path);
uint8_t packet_id(char* packet_name);

int peer_mode(
    char* ip, int port, char* main_path, uint8_t* key, 
    ddmode dd_default, std::map<uint8_t, ddmode>& dd_specific);

int main_mode(
    char* ip, int port, int peer_max,
    char* peer_path, char* subscriber_path, char* db_path, uint8_t* key,
    ddmode dd_default, std::map<uint8_t, ddmode>& dd_specific);

Hash hash(int bias, const void* mem, int len);
