# Routing Flags

The 32 bit `flags` field in an outgoing packet contains routing instructions for XRPL-Uplink to interpret.

The field consists of the following subfields:

Subfield | Bit start | Bit length | Description
---------|-----------|------------|------------
msg_type| 0|4|xrpl-uplink message type|
reserved|4|4|reserved - 0|
op code|8|8|see below|
operands|16|16|see below|

## Op codes

Each op-code changes the meaning of the operands data section.

Op code | Operand Bits | Description
--------|----------|------------
0 |           | send all peers
1 |           | send to all peers matching a `peermask`
| ^ | `Bit 0-8`  | reserved - 0
| ^ | `Bit 8-16` | bitmask for node pubkey ^
2 |            | send to `count` random peers
| ^ | `Bit 0-16` | count [uint16_t]
3 |            | send to the next peer in the round robin queue, increment subpeer counter by count ~
| ^ | `Bit 0-16` | count [uint16_t]
...|  | reserved|

* ^ peer bitmask works like a subnet mask but for peer node public key
* ~ subpeer counter moves the round robin to the next peer after it has been progressively incremented by 65536
