#include "uplink.h"

int print_usage(int argc, char** argv, const char* error)
{
    fprintf(stderr, 
    "XRPL-Uplink v%s by Richard Holland / XRPL-Labs\n%s%s"
    "An XRPL peer-protocol endpoint for connecting local subscribers (applications) to the XRPL mesh network.\n"
    "Usage:\n"
    "Main-mode:  The process that subscribers connect to. Maintains a swarm of peer mode processes up to max-peers\n"
    "  %s <max-peers> <peer-ip> <peer-port> [<default-ddmode> [mtPACKET:ddmode] ...] [sockdir=path] [dbdir=path]\n"
    "Peer-mode:  Connects over TCP/IP to a specified XRPL peer, then bridges that peerto the hub (main-mode process).\n"
    "  %s connect <peer-ip> <peer-port> [<default-ddmode> [mtPACKET:ddmode] ...] [sockdir=path]\n"
    "Path arguments:\n"
    "\tsockdir - directory in which peer.sock and subscriber.sock will be created or connected to\n"
    "\tdbdir   - (main mode only) directory in which peer database (list of seen and likely peers) are kept\n"
    "De-duplication modes (ddmode):\n"
    "\tall     - de-duplicate all packets in both directions (subscriber <-> peers)\n"
    "\tnone    - do not de-duplicate any packets in either direction\n"
    "\tpeer    - only de-duplicate inbound packets from peers (forward all duplicates from subscribers)\n"
    "\tsub     - only de-duplicate outgoing packets from subscribers (forward all duplicates from peers)\n"
    "Note: The first de-duplication mode specified on the command-line is the default mode applied to all packets\n"
    "Subsequent modes can be attached to specific packet types, e.g. mtGET_LEDGER:none mtTRANSACTION:all\n"
    "Packet Types:\n"
    "\tmtMANIFESTS mtPING mtCLUSTER mtENDPOINTS mtTRANSACTION mtGET_LEDGER mtLEDGER_DATA mtPROPOSE_LEDGER\n"
    "\tmtSTATUS_CHANGE mtHAVE_SET mtVALIDATION mtGET_OBJECTS mtGET_SHARD_INFO mtSHARD_INFO mtGET_PEER_SHARD_INFO\n"
    "\tmtPEER_SHARD_INFO mtVALIDATORLIST mtSQUELCH mtVALIDATORLISTCOLLECTION mtPROOF_PATH_REQ mtPROOF_PATH_RESPONSE\n"
    "\tmtREPLAY_DELTA_REQ mtREPLAY_DELTA_RESPONSE mtGET_PEER_SHARD_INFO_V2 mtPEER_SHARD_INFO_V2 mtHAVE_TRANSACTIONS\n"
    "\tmtTRANSACTIONS\n"
    "Example:\n"
    "       %s 10 r.ripple.com 51235 all mtGET_LEDGER:none\n",
    VERSION, (error ? error : ""), (error ? "\n" : ""), argv[0], argv[0], argv[0]); 
    return 1;
}

ddmode parse_dd(char* dd)
{
    if (strcmp(dd, "all") == 0)
        return DD_ALL;
    else if (strcmp(dd, "none") == 0)
        return DD_NONE;
    else if (strcmp(dd, "sub") == 0)
        return DD_SUB;
    else if (strcmp(dd, "peer") == 0)
        return DD_PEER;
    else
        return DD_INVALID;
}

#define TEST_HASH(x)\
    { \
        Hash h = hash(x, strlen(x));\
        printf("%.*s: ", 32, x);\
        for (int i = 0; i < 32; ++i)\
            printf("%02x", (unsigned char)(h.b[i]));\
        printf("\n");\
    }
int main(int argc, char** argv)
{

    TEST_HASH("hello world");
    TEST_HASH("hello world");
    TEST_HASH(
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world");

    TEST_HASH(
            "hello world hell1 world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world");
   
    return 0;

    if (argc < 4)
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

    ddmode dd_default = DD_ALL;
    if (argc >= 5)
        dd_default = parse_dd(argv[4]);

    if (dd_default == DD_INVALID)
    {
        print_usage(argc, argv, "default de-duplication mode may only be one of: all, none, sub, peer.");
        return 1;
    }

    std::map<int32_t, ddmode> dd_specific; // packet_type => de-duplication mode

    char sock_path[32]; sock_path[0] = '\0';
    char db_path[32]; db_path[0] = '\0';
    // parse dds and remaining arguments
    {
        for (int i = 5; i < argc; ++i)
        {
            char pktype[32]; pktype[0] = '\0'; char* pk = pktype;
            char ddtype[32]; ddtype[0] = '\0'; char* dd = ddtype;
            char* x = argv[i];
            for (; *x != '\0' && *x != ':' && *x != '=' && (pk - pktype < 31); *pk++ = *x++);

            int is_path = *x == '=';

            if (*x != ':' && *x != '=')
            {
                print_usage(argc, argv,
                    "invalid argment expecting packet:ddmode or sockdir=path or dbdir=path");
                return 1;
            }

            for (++x; *x != '\0' && (dd - ddtype < 31); *dd++ = *x++);
            *pk = '\0'; *dd = '\0';

            if (is_path)
            {
                if (strcmp(pktype, "sockdir") == 0)
                {
                    if (sock_path[0] != 0)
                    {
                        print_usage(argc, argv,
                            "sockdir specified more than once");
                        return 1;
                    }
                    
                    strcpy(sock_path, ddtype);
                }
                else if (strcmp(pktype, "dbdir") == 0)
                {
                    if (db_path[0] != 0)
                    {
                        print_usage(argc, argv,
                            "dbdir specified more than once");
                        return 1;
                    }
                    if (strcmp(argv[1], "connect") == 0)
                    {
                        print_usage(argc, argv,
                            "cannot specify dbdir in peer (connect) mode");
                        return 1;
                    }
                    strcpy(db_path, ddtype);
                }
                else
                {
                    print_usage(argc, argv,
                        "invalid argument expecting sockdir=path or dbdir=path");
                    return 1;
                }
            }
            else
            {
                int packet = packet_id(pktype);
                ddmode mode = parse_dd(ddtype);
                if (packet > -1 && mode != DD_INVALID)
                {
                    printf("packet: %d mode: %d\n", packet, mode);
                    dd_specific.emplace(packet, mode);
                }
                else
                {
                    print_usage(argc, argv,
                        "invalid specific de-duplication specified... check allowable dd/packet types.");
                    return 1;
                }
            }
        }
    }    

    if (db_path[0] == 0)
        strcpy(db_path, DEFAULT_DB_PATH);

    if (sock_path[0] == 0)
        strcpy(sock_path, DEFAULT_SOCK_PATH);

    
    // ensure socket path exists
    if (!(mkdir(sock_path, 0700) == 0 || errno == EEXIST))
    {
        fprintf(stderr, "Could not create directory: `%s` for socket files\n", sock_path);
        return 1;
    }

    
    int peer_max = 0;

    if (strlen(argv[1]) == 7 && memcmp(argv[1], "connect", 7) == 0)
    {
        // peer mode
        return peer_mode(ip, port, sock_path, dd_default, dd_specific);
    }
    else if (sscanf(argv[1], "%d", &peer_max) == 1 && peer_max > 1)
    {
        // main mode

        // ensure the db path exists
        if (!(mkdir(db_path, 0700) == 0 || errno == EEXIST))
        {
            fprintf(stderr, "Could not create directory: `%s` for database files\n", db_path);
            return 1;
        }

        // spawn first peer before continuing to main mode
        if (fork() == 0)
        {
            if (strcmp(sock_path, DEFAULT_SOCK_PATH) == 0)
            {
                // all our FDs are close on exec
                execlp(argv[0], argv[0], "connect", argv[2], argv[3], (char*)0);
            }
            else
            {
                char sock_arg[48];
                strcpy(sock_arg, "sockdir=");
                strcat(sock_arg, sock_path);

                // all our FDs are close on exec
                execlp(argv[0], argv[0], "connect", argv[2], argv[3], sock_arg, (char*)0);
            }

            // should be unreachable
            fprintf(stderr, "Execlp failed, could not spawn peer process\n");
            return 10;
        }

        // continue to main mode
        return main_mode(ip, port, peer_max, sock_path, db_path, dd_default, dd_specific);
    }
    else
    {
        print_usage(argc, argv, "max-peers must be at least 1");
        return 1;
    }

}

