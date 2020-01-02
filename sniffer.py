import sys
import socket
import struct
import errno
import hunter
import display
import yaraprocessor


# Start sniffing process
def start_sniffing():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    except socket.error as msg:
        print("Socket could not be created. Error Code : " + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    # Create a stdscr from curses
    stdscr = display.create_screen()
    # Create an instance from YARA processor
    try:
        p = yaraprocessor.Processor(['./rules/index.yar'])
    except IOError:
        print('File "./rules/index.yar" corrupted or does not exist')
        sys.exit()

    counter = {'pingSweep': 0, 'timeExceed': 0, 'unreachable': 0, 'deprecated': 0,
               'icmpUnreachableIncident': 0, 'icmpPacketTime': 0,
               'null': 0, 'xmas': 0, 'fin': 0, 'portScan': 0, 'synFlood': 0,
               'rstIncident': 0, 'rstPacketTime': 0,
               'synIncident': 0}
    sequence_num = {'seq1': 0, 'seq2': 0, 'seq3': 0, 'seq4': 0, 'seq5': 0, 'seq6': 0, 'seq7': 0, 'seq8': 0, 'seq9': 0,
                    'seq10': 0}
    sequence_numtime = {'time1': 0, 'time2': 0, 'time3': 0, 'time4': 0, 'time5': 0, 'time6': 0, 'time7': 0, 'time8': 0,
                        'time9': 0, 'time10': 0}
    yara_display = ''

    port_display = []

    display.display_screen(stdscr, counter, yara_display, port_display)

    # Sniff traffic
    while True:
        try:
            raw_data, addr = conn.recvfrom(65536)
        except IOError as e:
            if e.errno != errno.EINTR:
                raise

        dst_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        # Send the traffic to YARA scanner
        p.clear_results()
        yara_results = hunter.scan_traffic(raw_data, p)
        yara_display = get_yara_display(yara_results, yara_display)

        # 8 for IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

            # ICMP
            if proto == 1:
                # Flag the attack to be logged to threats log file
                log_it = False
                # Unpack the ICMP packet
                (icmp_type, code, checksum, data) = icmp_packet(data)
                (log_it, counter['pingSweep'], counter['timeExceed'], counter['unreachable'], counter['deprecated']) = \
                    hunter.detect_icmp(icmp_type, code, src, target, log_it, counter)
                if log_it:
                    hunter.log_attacks(proto, hunter.get_utc(), src_mac, dst_mac, src, target, icmp_type, code,
                                       checksum)
            # TCP
            elif proto == 6:
                # Flag the attack to be logged to threats log file
                log_it = False
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                 flag_fin, data) = tcp_segment(data)
                (log_it, counter['null'], counter['xmas'], counter['fin'], counter['portScan'], counter['synFlood'],
                 sequence_num, sequence_numtime) = hunter.detect_tcp(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                                                                     flag_fin, log_it, counter, src, target, sequence,
                                                                     sequence_num, sequence_numtime)
                # Port monitoring
                port_results = hunter.detect_ports(dest_port, src)
                port_display = get_port_display(port_results, port_display)

                # Log TCP attacks and detected ports
                if log_it:
                    hunter.log_attacks(proto, hunter.get_utc(), src_mac, dst_mac, src, target, src_port, dest_port,
                                       sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                                       flag_fin)

            # UDP
            elif proto == 17:
                (src_port, dest_port, size, data) = udp_segment(data)

            # Other
            else:
                pass
        else:
            pass
        display.display_screen(stdscr, counter, yara_display, port_display)


# Unpack ethernet frame
def ethernet_frame(data):
    dst_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dst_mac), get_mac_addr(src_mac), socket.htons(eth_proto), data[14:]


# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, \
           data[offset:]


# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Return properly formatted MAC address (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# Returns properly formatted IPv4 address (192.168.1.19)
def ipv4(addr):
    return '.'.join(map(str, addr))


# Properly format YARA results
def get_yara_display(yara_results, yara_display):
    for result in yara_results:
        if result not in yara_display:
            yara_display = yara_display + '  ' + result
    return yara_display


# Properly format ports results
def get_port_display(port_results, port_display):
    for result in port_results:
        for port in result:
            if port not in port_display:
                port_display.append(port)
    return port_display
