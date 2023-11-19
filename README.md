Copyright 2023 Maria Sfiraiala (maria.sfiraiala@stud.acs.upb.ro)

# Switch - Project1

## Description

The project aims to implement the three major roles of a level two switch:

1. switching frames based on the MAC address and the port associated with the path to it which are stored in the **CAM table**;

   There are 2 scenarios here:

   * Either the frame is unicast, in which case we should only flood the network with it, **only** if the destination doesn't already exist in our CAM table.
   This is necessary in order to somehow reach the target, while providing the route with the shortest path (flooding always finds it by design).

   * Or the frame is multicast/broadcast, in which case we flood it on every available port.

   > **Note**: We find whether the frame is unicast based off the LSB of the first byte in the destination MAC address.
   If the bit is not set, then the frame is unicast, otherwise it should be treated as multicast / broadcast.

1. switching frames based on the **VLANs** of the source port, destination port and in between path;

   This part of the implementation comes with little additions to the first one: we should only consider the ports that are either trunk, or with the same VLAN tag as the source and destination.

   The switch inserts and deletes the VLAN tag when it reaches access mode ports (in other words, the ones to the end devices in our topology).

   > **Note**: We decided to keep a tagged and untagged frame for every forwarding we perform in order to send the proper one, based on the characteristics of the link.

1. switching frames based on listening and blocked ports, part of **STP**, as to not flood the network with too many packets from interconnected switches.

   Now here comes the fun part:

   We were able to construct our own (kinda personalized) BDPU frames inside the `BDPU_CONFIG` part of the payload and we decided to send **only** the most important information:

   * the current root bridge prio

   * the current root bridge path cost

   * the sender prio

   The rest of the payload is zeroed out in order to still preserve the traditional structure of the STP frame:

   ```Python
   dest_mac =  binascii.unhexlify("01:80:c2:00:00:00".replace(':', ''))
   macs = dest_mac + switch.mac
   llc = struct.pack("!H3b", 38, 0x42, 0x42, 0x03)
   bpdu = bytes(5) + struct.pack("!QIQ", root_bridge_ID, root_path_cost, switch.prio) + bytes(10)
   data = macs + llc + bpdu
   ```

## Observations Regarding the Project

I really really enjoyed working on this project.
The Python experience was fun and I feel that I've learnt a lot about it whilst writing (scripting?) stuff out.
Found out how debugging works and that conversion to and from bytes is kinda nasty.

I wish the team would upgrade the Python version used for the automated tests (come on, we aren't living in the Stone Age anymore, give us something over `3.10`), but other than that, the synchronization was top notch, thanks a lot!
