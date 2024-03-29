#!/usr/bin/python3

import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name
from dataclasses import dataclass
import copy
import binascii

import pdb

root_bridge_ID = 0
root_path_cost = 0
root_port = 0

class Switch:
    def __init__(self, prio, vlans, mac):
        self.prio = prio
        self.vlans = vlans
        self.mac = mac

class Frame:
    def __init__(self, dest_mac, src_mac, vlan_id, data):
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.vlan_id = vlan_id
        self.data = data

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    # dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)


def receive_bpdu(switch, data, port):
    global root_bridge_ID, root_path_cost, root_port
    bpdu_root_bridge, bpdu_root_path, bpdu_bridge = struct.unpack("!QIQ", data[22 : 42])

    if bpdu_root_bridge < root_bridge_ID:
        root_path_cost = bpdu_root_path + 10
        root_port = port

        # If we were root bridge, and we aren't anymore, we should block all the ports
        # that aren't the root port
        if switch.prio == root_bridge_ID:
            for port, info in switch.vlans.items():
                if info[1] == "T" and port != root_port:
                    new_info = (info[0], info[1], "BLOCKED")
                    switch.vlans[port] = new_info

        # Update the root bridge ID with the new winner
        root_bridge_ID = bpdu_root_bridge

        switch.vlans[root_port] = (switch.vlans[root_port][0], switch.vlans[root_port][1], "ROOT")

        for port, info in switch.vlans.items():
            if info[1] == "T" and info[2] != "BLOCKED" and port != root_port:
                send_bpdu(port, switch)

    elif bpdu_root_bridge == root_bridge_ID:
        if port == root_port and bpdu_root_path + 10 < root_path_cost:
            root_path_cost = bpdu_root_path + 10

        elif port != root_port:
            if bpdu_root_path > root_path_cost:
                switch.vlans[port] = (switch.vlans[port][0], switch.vlans[port][1], "DESIGNATED")

    elif bpdu_bridge == switch.prio:
        switch.vlans[port] = (switch.vlans[port][0], switch.vlans[port][1], "BLOCKED")

    if switch.prio == root_bridge_ID:
        for port, info in switch.vlans.items():
            new_info = (info[0], info[1], "DESIGNATED")
            switch.vlans[port] = new_info


def send_bpdu(port, switch):
    dest_mac =  binascii.unhexlify("01:80:c2:00:00:00".replace(':', ''))
    macs = dest_mac + switch.mac
    llc = struct.pack("!H3b", 38, 0x42, 0x42, 0x03)
    bpdu = bytes(5) + struct.pack("!QIQ", root_bridge_ID, root_path_cost, switch.prio) + bytes(10)

    data = macs + llc + bpdu
    send_to_link(port, data, len(data))


def send_bdpu_every_sec(switch):
    while root_bridge_ID == switch.prio:
        for port, info in switch.vlans.items():
            if info[1] == "T":
                send_bpdu(port, switch)
        time.sleep(1)


def initialize_bridge(switch):
    global root_bridge_ID, root_path_cost

    for port, info in switch.vlans.items():
        if info[1] == "T":
            new_info = (info[0], info[1], "BLOCKED")
            switch.vlans[port] = new_info

    root_bridge_ID = switch.prio
    root_path_cost = 0

    if switch.prio == root_bridge_ID:
        for port, info in switch.vlans.items():
            new_info = (info[0], info[1], "DESIGNATED")
            switch.vlans[port] = new_info


def get_vlans(switch_id, interfaces_names):
    file = open('configs/switch{}.cfg'.format(switch_id), "r")
    lines = file.readlines()
    prio = int(lines[0].strip())
    vlans = {}

    # Get some useful information about the ports, their names
    # and their VLAN
    for l in lines[1:]:
        name, vlan = l.split()
        vlans[interfaces_names[name]] = (name, vlan, "")

    return Switch(prio, vlans, None)


def unicast(mac):
    mac_int = int.from_bytes(mac, byteorder="big")
    return ((mac_int >> 40) & 0b01 == 0)


def vlan_switch(interfaces, cam_table, frame, port, switch):
    # We received a frame on a blocked port, impossible!, we drop it
    if switch.vlans[port][2] == "BLOCKED":
        return

    cam_table[frame.src_mac] = port

    # If the frame is unicast, we should send it only to the destination
    # (if we have its MAC address already stored)
    if unicast(frame.dest_mac):
        if frame.dest_mac in cam_table:
            # Get the vlans of both the source and the destination ports, plus
            # the state of the link (blocked, designated, root)
            v_src = switch.vlans[cam_table[frame.src_mac]][1]
            v_dst = switch.vlans[cam_table[frame.dest_mac]][1]
            state = switch.vlans[cam_table[frame.dest_mac]][2]

            copy_frame = copy.deepcopy(frame)

            if frame.vlan_id == -1:
                frame.vlan_id = int(v_src)
                untagged_frame = frame.data
                tagged_frame = frame.data[0:12] + create_vlan_tag(frame.vlan_id) + frame.data[12:]
            else:
                untagged_frame = frame.data[0:12] + frame.data[16:]
                tagged_frame = frame.data[0:12] + create_vlan_tag(frame.vlan_id) + frame.data[16:]

            if v_dst == "T":
                if state != "BLOCKED":
                    send_to_link(cam_table[frame.dest_mac], tagged_frame, len(tagged_frame))
                else:
                    frame = copy_frame
            elif int(v_dst) == frame.vlan_id:
                send_to_link(cam_table[frame.dest_mac], untagged_frame, len(untagged_frame))
            else:
                frame = copy_frame

        # When we don't have the MAC address of the destination already stored, we should
        # flood the entire network in order to make sure the packet eventually reaches the
        # destination
        else:
            for p in interfaces:
                if p != port:
                    v_src = switch.vlans[cam_table[frame.src_mac]][1]
                    v_dst = switch.vlans[p][1]
                    state = switch.vlans[p][2]

                    copy_frame = copy.deepcopy(frame)

                    if frame.vlan_id == -1:
                        frame.vlan_id = int(v_src)
                        untagged_frame = frame.data
                        tagged_frame = frame.data[0:12] + create_vlan_tag(frame.vlan_id) + frame.data[12:]
                    else:
                        untagged_frame = frame.data[0:12] + frame.data[16:]
                        tagged_frame = frame.data[0:12] + create_vlan_tag(frame.vlan_id) + frame.data[16:]

                    if v_dst == "T":
                        if state != "BLOCKED":
                            send_to_link(p, tagged_frame, len(tagged_frame))
                        else:
                            frame = copy_frame
                    elif int(v_dst) == frame.vlan_id:
                        send_to_link(p, untagged_frame, len(untagged_frame))
                    else:
                        frame = copy_frame
    # The frame is not unicast, so we flood it
    else:
        for p in interfaces:
            if p != port:
                v_src = switch.vlans[cam_table[frame.src_mac]][1]
                v_dst = switch.vlans[p][1]
                state = switch.vlans[p][2]

                copy_frame = copy.deepcopy(frame)

                if frame.vlan_id == -1:
                    frame.vlan_id = int(v_src)
                    untagged_frame = frame.data
                    tagged_frame = frame.data[0:12] + create_vlan_tag(frame.vlan_id) + frame.data[12:]
                else:
                    untagged_frame = frame.data[0:12] + frame.data[16:]
                    tagged_frame = frame.data[0:12] + create_vlan_tag(frame.vlan_id) + frame.data[16:]

                if v_dst == "T":
                    if state != "BLOCKED":
                        send_to_link(p, tagged_frame, len(tagged_frame))
                    else:
                        frame = copy_frame
                elif int(v_dst) == frame.vlan_id:
                    send_to_link(p, untagged_frame, len(untagged_frame))
                else:
                    frame = copy_frame


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    # Associate the interface name with their ID, useful for
    # constructing the CAM table and VLAN switching
    interfaces_names = {}
    for i in interfaces:
        interfaces_names[get_interface_name(i)] = i

    switch = get_vlans(switch_id, interfaces_names)
    switch.mac = get_switch_mac()
    initialize_bridge(switch)
    cam_table = {}

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(switch,))
    t.start()

    while True:
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        frame = Frame(dest_mac, src_mac, vlan_id, data)

        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Check if we received a BDPU packet or something else
        if dest_mac == "01:80:c2:00:00:00":
            receive_bpdu(switch, data, interface)
        else:
            vlan_switch(interfaces, cam_table, frame, interface, switch)
    t.join()


if __name__ == "__main__":
    main()
