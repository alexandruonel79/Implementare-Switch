#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name
# mac dest for bpdu package
dest_mac_bytes = bytes([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00])
# list that has all the trunk ports the switch has
trunk_ports = []
own_bridge_ID = -1
root_bridge_ID = -1
root_path_cost = -1
root_port = -1
# only trunk ports have a port state
# it s either BLOCKED or DESIGNATED
port_state = {}

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
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

def create_bdpu_package(sender_bridge_ID, port, root_path_cost, root_bridge_ID):
    # created the package with the default stp structure
    # followed the standard
    global dest_mac_bytes
    # constants
    STP  = b"\x42"
    CONTROL = 3
    bytes_logical_link = STP
    bytes_logical_link += STP
    bytes_logical_link += CONTROL.to_bytes(1, byteorder='big')
    # needed an int variable
    ZERO = 0
    bytes_BPDU_header = ZERO.to_bytes(2, byteorder='big')
    bytes_BPDU_header += ZERO.to_bytes(1, byteorder='big')
    bytes_BPDU_header += ZERO.to_bytes(1, byteorder='big')

    # config is set to zero
    bytes_BPDU_CONFIG = ZERO.to_bytes(1, byteorder='big')
    # root bridge id
    bytes_BPDU_CONFIG += (int(root_bridge_ID)).to_bytes(8, byteorder='big')
    # path cost
    bytes_BPDU_CONFIG += (int(root_path_cost)).to_bytes(4, byteorder='big')
    # current switch id's
    bytes_BPDU_CONFIG += (int(sender_bridge_ID)).to_bytes(8, byteorder='big')

    MESSAGE_AGE = 1
    MAX_AGE = 20
    HELLO_TIME = 2
    FORWARD_DELAY = 15
    # set this ones same as in wireshark frame
    bytes_BPDU_CONFIG += port.to_bytes(2, byteorder='big')
    bytes_BPDU_CONFIG += MESSAGE_AGE.to_bytes(2, byteorder='big')
    bytes_BPDU_CONFIG += MAX_AGE.to_bytes(2, byteorder='big')
    bytes_BPDU_CONFIG += HELLO_TIME.to_bytes(2, byteorder='big')
    bytes_BPDU_CONFIG += FORWARD_DELAY.to_bytes(2, byteorder='big')

    LLC_LENGTH  = 38
    # return all the package
    return dest_mac_bytes + get_switch_mac() + LLC_LENGTH.to_bytes(2, byteorder='big') +  bytes_logical_link + bytes_BPDU_header + bytes_BPDU_CONFIG

def send_bdpu_every_sec():
    global root_bridge_ID
    global own_bridge_ID
    global root_path_cost

    while True:
        # checked if root_bridge_ID and the other variables are initialised
        if own_bridge_ID is root_bridge_ID and root_bridge_ID != -1 and root_path_cost != -1:
            for port in trunk_ports:
                root_bridge_ID = own_bridge_ID
                sender_bridge_ID = own_bridge_ID
                root_path_cost = 0
                # send the package
                package = create_bdpu_package(sender_bridge_ID, port, root_path_cost, root_bridge_ID)
                send_to_link(port, package, 52)

        time.sleep(1)

# i chose to have only BLOCKED and DESIGNATED ports
def handle_BDPU_packet_received(BPDU_root_bridge_ID, BPDU_sender_path_cost, interface_from, BPDU_sender_bridge_ID):
    # get the global variables
    global root_bridge_ID
    global own_bridge_ID
    global root_path_cost
    global root_port
    # the stp algorithm is the one from the pseudocode 

    # check if we were the root bridge
    weWereRootBridge = (root_bridge_ID == own_bridge_ID)

    if BPDU_root_bridge_ID < int(root_bridge_ID):
        root_bridge_ID = BPDU_root_bridge_ID
        # add 10 to cost because link speed is 100 Mbps
        root_path_cost = BPDU_sender_path_cost + 10 
        root_port = interface_from

        if weWereRootBridge:
            for i in trunk_ports:
                if i != root_port:
                    port_state[i] = 'BLOCKED'

        if port_state[root_port] == 'BLOCKED':
            port_state[root_port] = 'DESIGNATED'
        
        for port in trunk_ports:
            package = create_bdpu_package(own_bridge_ID, port, root_path_cost, root_bridge_ID)
            send_to_link(port, package, len(package))

    elif BPDU_root_bridge_ID == root_bridge_ID:
        if interface_from == root_port and BPDU_sender_path_cost + 10 < root_path_cost:
            root_path_cost = BPDU_sender_path_cost + 10
        elif interface_from != root_port:
            if BPDU_sender_path_cost > root_path_cost:
                if port_state[interface_from] == 'BLOCKED':
                    port_state[interface_from] = 'DESIGNATED'

    elif BPDU_sender_bridge_ID == own_bridge_ID:
        port_state[interface_from] = 'BLOCKED'

    else:
        return
    
    if own_bridge_ID == root_bridge_ID:
        for port in trunk_ports:
            port_state[port] = 'DESIGNATED'

# checks if it's a unicast, by checking the parity    
def is_unicast(dest_mac):
     if (int(dest_mac[:2], 16)) % 2 == 0:
         return True
     return False

def read_switch_info(switch_id):
    file_path = f'configs/switch{switch_id}.cfg'

    with open(file_path, 'r') as file:
        file_contents = file.read()
        return file_contents

def extract_BDPU_packet_info(data):
    # extract all the necessary info and return it as a list
    BPDU_root_bridge_ID = data[22:30]
    BDPU_sender_path_cost = data[30:34]
    BPDU_sender_bridge_ID = data[34:42]

    return [int.from_bytes(BPDU_root_bridge_ID, 'big'), int.from_bytes(BDPU_sender_path_cost, 'big'), int.from_bytes(BPDU_sender_bridge_ID, 'big')]


def main():
    global root_bridge_ID
    global own_bridge_ID
    global root_path_cost
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    # contains set with the pair mac address and an interface
    vlan_mac_table = []

    for i in interfaces:
        # append an empty dictionary for every vlan
        # my number of maximum vlans is set to the number of interfaces
        # considered it enough
        vlan_mac_table.append({})

    file_data = read_switch_info(switch_id).split('\n')
    # get the priority from sw config
    switch_priority = file_data[0]

    interface_types_dict = {}

    for i in interfaces:
        line_split = file_data[i + 1].split(' ')
        if len(line_split) == 2:
            interface_types_dict[line_split[0]] = line_split[1]
            # set all ports to blocking (STP)
            if line_split[1] == 'T':
                trunk_ports.append(i)
                port_state[i] = 'BLOCKED'

    own_bridge_ID =  switch_priority
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0
 
    # initialise
    if own_bridge_ID == root_bridge_ID:
        for port in trunk_ports:
            port_state[port] = 'DESIGNATED'
    
    
    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    while True:
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        # if it's equal to special bpdu mac dest
        # (first global variable)
        if dest_mac == dest_mac_bytes:
            BPDU_root_bridge_ID, BPDU_sender_path_cost, BPDU_sender_bridge_ID = extract_BDPU_packet_info(data)
            handle_BDPU_packet_received(BPDU_root_bridge_ID, BPDU_sender_path_cost, interface, BPDU_sender_bridge_ID)
            continue

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        cameFromTrunk = False
        
        if interface_types_dict[get_interface_name(interface)] == 'T':
            cameFromTrunk = True
        else:
            vlan_id = int(interface_types_dict[get_interface_name(interface)])

        if(cameFromTrunk == True and port_state[interface] == 'BLOCKED'):
            continue
        
        vlan_mac_table[vlan_id][src_mac] = interface
            
        # check the type of packet
        if is_unicast(dest_mac):
            # check if we have the mac in the table
            if dest_mac in vlan_mac_table[vlan_id]:
                # check if its not blocked
                if interface_types_dict[get_interface_name(vlan_mac_table[vlan_id][dest_mac])] == 'T' and port_state[vlan_mac_table[vlan_id][dest_mac]] != 'BLOCKED':
                    # two possibilities: if it comes from trunk we send it the same, if not add it s 802.1q
                    if cameFromTrunk == True:
                        send_to_link(vlan_mac_table[vlan_id][dest_mac], data, length)
                    else:
                        send_to_link(vlan_mac_table[vlan_id][dest_mac], data[:12] + create_vlan_tag(vlan_id) + data[12:], length + 4)
                else:
                    # two possibilities: if it comes from trunk we remove the vlan tag, if not send it directly
                    if cameFromTrunk == True:
                        send_to_link(vlan_mac_table[vlan_id][dest_mac], data[:12] + data[16:], length - 4)
                    else:
                        send_to_link(vlan_mac_table[vlan_id][dest_mac], data, length)
            else:
                for o in interfaces:
                    if o != interface:
                        # check if its not blocked
                        if interface_types_dict[get_interface_name(o)] == 'T' and port_state[o] != 'BLOCKED':
                            # two possibilities: if it comes from trunk we send it the same, if not add it s 802.1q
                            if cameFromTrunk == True:
                                send_to_link(o, data, length)
                            else:
                                send_to_link(o, data[:12] + create_vlan_tag(vlan_id) + data[12:], length + 4)
                        elif interface_types_dict[get_interface_name(o)] == str(vlan_id):
                            # two possibilities: if it comes from trunk we remove the vlan tag, if not send it directly
                            if cameFromTrunk == True:
                                send_to_link(o, data[:12] + data[16:], length - 4)
                            else:
                                send_to_link(o, data, length)

        else:
            for o in interfaces:
                if o != interface:
                    # check if its not blocked
                    if interface_types_dict[get_interface_name(o)] == 'T' and port_state[o] != 'BLOCKED':
                        # two possibilities: if it comes from trunk we send it the same, if not add it s 802.1q
                        if cameFromTrunk == True:
                            send_to_link(o, data, length)
                        else:
                            send_to_link(o, data[:12] + create_vlan_tag(vlan_id) + data[12:], length + 4)
                    elif interface_types_dict[get_interface_name(o)] == str(vlan_id):
                        # two possibilities: if it comes from trunk we remove the vlan tag, if not send it directly
                        if cameFromTrunk == True:
                            send_to_link(o, data[:12] + data[16:], length - 4)
                        else:
                            send_to_link(o, data, length)

if __name__ == "__main__":
    main()
