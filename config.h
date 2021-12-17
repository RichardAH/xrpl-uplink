#define VERSION             "0.1"
#define DEFAULT_SOCK_PATH   "/var/run/xrpl-uplink"
#define DEFAULT_DB_PATH     "/var/lib/xrpl-uplink"
#define PEER_FN             "peer.sock"
#define SUBSCRIBER_FN       "subscriber.sock"
#define DB_FN               "peer.db"
#define KEY_FN              "peer.key"
#define USER_AGENT          "xrpl-uplink"
#define MAX_FDS 1024
#define POLL_TIMEOUT 2000 /* ms */
#define MAX_TIMEOUTS 20 // number of times poll can timeout before quit
#define DEFAULT_BUF_SIZE 64
#define DEBUG 0
#define VERBOSE_DEBUG 0
#define HTTP_BUFFER_SIZE 4096
#define SSL_BUFFER_SIZE 65536
#define PACKET_BUFFER_NORM 65536
#define PACKET_BUFFER_MAX  67108864

// seen hash cache eviction parameters
#define EVICTION_MAX 16
#define EVICTION_TIME 60 // eviction active after 500 seconds
#define EVICTION_SPINS 5 // attempt to randomly evict 5 old entries for each inserted key

