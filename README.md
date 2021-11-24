# xrpl-uplink (WIP)
A per-machine XRPL peer-protocol bridge connecting local applications (_subscribers_) with remote XRPL _peers_ via a standardized unix domain socket interface.

Uplink has the following core responsibilities:
  1. PEERING - Maintain connections to a specified number of XRPL peers.
  
      1a. Perform pings and pongs.
      
      1b. Maintain a database of likely peers.
      
      1c. Processes mtENDPOINT messages and use these to crawl additional _peers_.
      
  2. RECEIVING - De-duplicate incoming packets from _peers_ and forward them to all _subscribers_.
  3. SENDING - Duplicate outgoing packets from _subscribers_ and forward them to all connected _peers_.
  
  For more info see design.md
