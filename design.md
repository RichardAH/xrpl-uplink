```
Main Life-cycle:

1.  Create main process (M)
    ./uplink <max peer count> [ <start peer ip> <start peer port> ]

Peer Life-cycle:

1.  Main process creates peer process (P)
    ./uplink connect peer-ip peer-port

2.  P connects to M via /var/run/xrpl-uplink/peer.sock

3.  If P disconnects the unix domain socket it dies and is considered a dead peer.

4.  P connects to the peer ip/port over TCP/IP, handles all pings and pongs and packet decompression.

5.  P forwards all non-ping packets to M over peer.sock.

6.  M de-duplicates packets from P's.

7.  M processes any mtENDPOINT messages forwarded by a P, and uses it to populate /var/lib/xrpl-uplink/peers

8.  M creates more P processes to connect to more unique peers up to the max limit specified at cmdline.

Subscriber Life-cycle:

1. Subscribers (S) describe any application on the system that desires reilable clean access to the XRPL mesh.

2. S connects to M via /var/run/xrpl-uplink/subscriber.sock

3. M sends each deduplicated packet from the set of all P's to the set of all S's.

4. M sends each packet from any S to all P's.

5. A disconnected subscriber is immediately considered dead.
```


## Inter-process packet header format
offset | size | field
-|-|-
0|4|timestamp
4|4|flags
8|4|payload length
12|2|packet type
14|2|port (if applicable)
16|16|inet addr (if applicable)
32|32|packet hash
64|32|peer from (may be null when subscriber sends)
96|32|peer to ^
total|128|
^ peer to may be null to send to all peers, or it may be a mask as determined by flags
