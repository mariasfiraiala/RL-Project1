#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name
from dataclasses import dataclass

@dataclass
class Switch:
    prio: int
    vlans: dict[int, (str, str)]

@dataclass
class Frame:
    dest_mac: bytes
    src_mac: bytes
    vlan_id: int
    data: bytes
    len: int

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

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)


def get_vlans(switch_id, interfaces_names):
    file = open('configs/switch{}.cfg'.format(switch_id), "r")
    prio = int(file.readlines()[0].strip())
    switch = {}
    for l in file.readlines()[1:]:
        name, vlan = l.split()
        switch[interfaces_names[name]] = (name, vlan)

    return Switch(prio, switch)


def unicast(mac):
    return not (mac >> 40 & 0b00)


def vlan_switch(interfaces, cam_table, frame, port, switch):
    cam_table[frame.src_mac] = port
    if unicast(frame.dest_mac):
        if frame.dest_mac in cam_table:
            v = switch.vlans[cam_table[frame.dest_mac]][1]

            # TODO: Think about the frame that ALREADY has a tag
            if v == "T":
                tagged_frame = frame.data[0:12] + create_vlan_tag(frame.vlan_id) + frame.data[12:]
                send_to_link(cam_table[frame.dest_mac], tagged_frame, frame.len + 4)
            elif int(v) == frame.vlan_id:
                send_to_link(cam_table[frame.dest_mac], frame.data, frame.len)
        else:
            for p in interfaces:
                if p != port:
                    v = switch.vlans[p][1]
                    if v == "T":
                        tagged_frame = frame.data[0:12] + create_vlan_tag(frame.vlan_id) + frame.data[12:]
                        send_to_link(cam_table[frame.dest_mac], tagged_frame, frame.len + 4)
                    elif int(v) == frame.vlan_id:
                        send_to_link(cam_table[frame.dest_mac], frame.data, frame.len)
    else:
         for p in interfaces:
            if p != port:
                v = switch.vlans[p][1]
                if v == "T":
                    tagged_frame = frame.data[0:12] + create_vlan_tag(frame.vlan_id) + frame.data[12:]
                    send_to_link(cam_table[frame.dest_mac], tagged_frame, frame.len + 4)
                elif int(v) == frame.vlan_id:
                    send_to_link(cam_table[frame.dest_mac], frame.data, frame.len)



def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    interfaces_names = {}
    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))
        interfaces_names[get_interface_name(i)] = i

    switch = get_vlans(switch_id, interfaces_names)
    cam_table = {}

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        frame = Frame(dest_mac, src_mac, vlan_id, data, length)
        vlan_switch(interfaces, cam_table, frame, interface, switch)

        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, data, length)

if __name__ == "__main__":
    main()
