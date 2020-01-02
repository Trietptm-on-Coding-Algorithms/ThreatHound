import datetime
import time
import sys
import socket
import curses


# Detect ICMP attacks
def detect_icmp(icmp_type, icmp_code, src, target, log_it, counter):
    # Detecting Ping Sweeps
    # ping xxx.xxx.xxx.xxx
    if icmp_type == 8 and target == get_ip():
        log_it = True
        counter['pingSweep'] += 1

    # Detecting traffic with TTL exceeded
    #elif icmp_type == 11 and target == get_ip():
    #    log_it = True
    #    counter['timeExceed'] += 1

    # Detecting more than 2 ICMP Destination Unreachable packets in 3 seconds p#960 (host only reply with type 2 or 3)
    # nmap -sU xxx.xxx.xxx.xxx
    elif (icmp_type == 3 and src == get_ip() and int(time.time()) <= counter['icmpPacketTime'] + 3) and \
            ((icmp_code == 2) or (icmp_code == 3)):
        counter['icmpUnreachableIncident'] += 1
        if counter['icmpUnreachableIncident'] >= 2:
            log_it = True
            counter['unreachable'] += 1

    # If more than 3 seconds difference between ICMP Unreachable then do not count it as an attack
    elif (icmp_type == 3 and src == get_ip() and int(time.time()) > counter['icmpPacketTime']) and \
            ((icmp_code == 2) or (icmp_code == 3)):
        counter['icmpUnreachableIncident'] = 0
        counter['icmpPacketTime'] = int(time.time())

    # Detecting ICMP deprecated
    #elif icmp_type == 4 and src == get_ip():
    #    log_it = True
    #    counter['deprecated'] += 1

    else:
        pass
    return log_it, counter['pingSweep'], counter['timeExceed'], counter['unreachable'], counter['deprecated']


# Detect TCP attacks
def detect_tcp(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, log_it, counter, src, target, seq, seqNumDic,
               seqNumTimeDic):
    # Detecting more than 40 TCP packets with RST flag within 3 seconds
    # nmap -sS xxx.xxx.xxx.xxx
    if flag_rst == 1 and flag_psh == 0 and int(time.time()) <= counter['rstPacketTime'] + 1 \
            and src == get_ip():
        counter['rstIncident'] += 1
        if counter['rstIncident'] >= 40:
            log_it = True
            counter['portScan'] += 1

    # Resetting counters if the above condition wasn't met
    elif flag_rst == 1 and flag_syn == 0 and flag_psh == 0 and src == get_ip():
       # counter['rstIncident'] = 0
        counter['rstPacketTime'] = int(time.time())

    # Detecting TCP packet with SYN Flag and storing up to 10 sequence numbers in seqNumDic and time in seqNumTimeDic
    # nmap -sS 80 xxx.xxx.xxx.xxx
    if flag_syn == 1 and flag_ack == 0 and flag_psh == 0 and flag_rst == 0 and target == get_ip():
        for typeW, valueW in seqNumDic.items():
            if valueW == 0:
                seqNumDic[valueW] = seq + 1
                seqNumTimeDic[valueW] = int(time.time())
                break

    # Detecting TCP packet with ACK flag that have the same seq of previously captured sequence numbers
    if flag_syn == 0 and flag_ack == 1 and flag_psh == 0 and flag_rst == 0 and target == get_ip():
        for typeX, valueX in seqNumDic.items():
            if valueX == seq:
                seqNumDic[valueX] = 0
                seqNumTimeDic[valueX] = 0
                break

        # Checking to see if 10 seconds passed since all the sequence numbers has been stored
        for typeY, valueY in seqNumTimeDic.items():
            if int(time.time()) - 10 > valueY > 0:
                counter['synIncident'] += 1

        # If all stored sequence numbers has been there for 10 seconds, consider this a SYN Flood attack and reset
        # values to store more
        if counter['synIncident'] == 10:
            counter['synFlood'] += 1
            counter['synIncident'] = 0
            for typeZ, valueZ in seqNumDic.items():
                valueZ = 0
                seqNumTimeDic[valueZ] = 0
    # Detect null Scan
    # nmap -N xxx.xxx.xxx.xxx
    if flag_urg == 0 and flag_psh == 0 and flag_fin == 0 and flag_ack == 0 and flag_rst == 0 and flag_syn == 0 and target == get_ip():
        log_it = True
        counter['null'] += 1

    # Detect XMAS Scan
    # nmap -X xxx.xxx.xxx.xxx
    if flag_urg == 1 and flag_psh == 1 and flag_fin == 1:
        log_it = True
        counter['xmas'] += 1

    # Detect FIN Scan (all other flags 0 to avoid false positives)
    # nmap -F xxx.xxx.xxx.xxx
    if flag_urg == 0 and flag_psh == 0 and flag_fin == 1 and flag_ack == 0 and flag_rst == 0 and flag_syn == 0:
        log_it = True
        counter['fin'] += 1

    return log_it, counter['null'], counter['xmas'], counter['fin'], counter['portScan'], counter['synFlood'], \
           seqNumDic, seqNumTimeDic


# Scan traffic by YARA
def scan_traffic(data, p):
    p.data = data
    p.analyze()
    if p.results:
        for match in p.results:
            log_attacks('yara', get_utc(), match['subtype'], match['strings'], match['result'])
            yield match['result']


# Parse ports file
def detect_ports(dst_port, src):
    from configparser import ConfigParser
    parser = ConfigParser()
    parser.read('ports')

    port_number = []
    port_description = []

    for section_name in parser.sections():
        for name, value in parser.items(section_name):
            port_number.append(value)
            port_description.append(name.upper())

    match = [port for port in port_number if str(dst_port) == port]

    if match:
        index = port_number.index(match[0])
        match.append(port_description[index])
        log_attacks('port', get_utc(), src, match[0], match[1])
        yield match


# Log detected attacks
def log_attacks(proto, *args):
    # Create the log file on the local directory if not exists
    from pathlib import Path

    log_file = Path('/var/log/threathound-%s' % datetime.date.today())

    try:
        if log_file.is_file():
            fout = open('/var/log/threathound-%s' % datetime.date.today(), 'at')
        else:
            fout = open('/var/log/threathound-%s' % datetime.date.today(), 'wt')
    except Exception as msg:
        print('\nError while creating/opening log file under "/var/log" directory: ', msg)
        curses.endwin()

    # Check for ICMP proto
    if proto == 1:
        if args[5] == 8:
            print('{0} Src_MAC={1} Dst_MAC={2} Src_IP={3} Dst_IP={4} ICMP_Type={5} Code={6} Checksum={7}'
                  ' Attck=Ping Sweep'.format(str(args[0]), str(args[1]), str(args[2]), str(args[3]), str(args[4]),
                                             str(args[5]), str(args[6]), str(args[7])), file=fout)
        #elif args[6] == 11:
        #    print('{0} Src_MAC={1} Dst_MAC={2} Src_IP={3} Dst_IP={4} ICMP_Type={5} Code={6} Checksum={7}'
        #          ' Attck=TTL Exceeded'.format(str(args[0]), str(args[1]), str(args[2]), str(args[3]), str(args[4]),
        #                                      str(args[5]), str(args[6]), str(args[7])), file=fout)
        elif args[6] == 3:
            print('{0} Src_MAC={1} Dst_MAC={2} Src_IP={3} Dst_IP={4} ICMP_Type={5} Code={6} Checksum={7}'
                  ' Attck=ICMP Unreachable'.format(str(args[0]), str(args[1]), str(args[2]), str(args[3]), str(args[4]),
                                                   str(args[5]), str(args[6]), str(args[7])), file=fout)
        #elif args[6] == 4:
        #    print('{0} Src_MAC={1} Dst_MAC={2} Src_IP={3} Dst_IP={4} ICMP_Type={5} Code={6} Checksum={7}'
        #          ' Attck=Ping of Death'.format(str(args[0]), str(args[1]), str(args[2]), str(args[3]), str(args[4]),
        #                                        str(args[5]), str(args[6]), str(args[7])), file=fout)
        else:
            print('{0} Src_MAC={1} Dst_MAC={2} Src_IP={3} Dst_IP={4} ICMP_Type={5} Code={6} Checksum={7}'
                  ' Attck=Other'.format(str(args[0]), str(args[1]), str(args[2]), str(args[3]), str(args[4]),
                                        str(args[5]), str(args[6]), str(args[7])), file=fout)

    # Check for TCP proto flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin
    if proto == 6:
        if args[12] == 1:
            print('{0} Src_MAC={1} Dst_MAC={2} Src_IP={3} Dst_IP={4} Src_Port={5} Dst_Port={6} Seq={7} ACK_No={8}'
                  ' URG={9} ACK={10} PUSH={11} RST={12} SYN={13} FIN={14}'
                  ' Attck=Port Scan'.format(str(args[0]), str(args[1]), str(args[2]), str(args[3]), str(args[4]),
                                            str(args[5]), str(args[6]), str(args[7]), str(args[8]), str(args[9]),
                                            str(args[10]), str(args[11]), str(args[12]), str(args[13]),
                                            str(args[14])), file=fout)
        elif args[13] == 1:
            print('{0} Src_MAC={1} Dst_MAC={2} Src_IP={3} Dst_IP={4} Src_Port={5} Dst_Port={6} Seq={7} ACK_No={8}'
                  ' URG={9} ACK={10} PUSH={11} RST={12} SYN={13} FIN={14}'
                  ' Attck=SYN Flood'.format(str(args[0]), str(args[1]), str(args[2]), str(args[3]), str(args[4]),
                                            str(args[5]), str(args[6]), str(args[7]), str(args[8]), str(args[9]),
                                            str(args[10]), str(args[11]), str(args[12]), str(args[13]),
                                            str(args[14])), file=fout)
        elif args[9] == 0 and args[10] == 0 and args[11] == 0 and args[12] == 0 and args[13] == 0 and args[14] == 0:
            print('{0} Src_MAC={1} Dst_MAC={2} Src_IP={3} Dst_IP={4} Src_Port={5} Dst_Port={6} Seq={7} ACK_No={8}'
                  ' URG={9} ACK={10} PUSH={11} RST={12} SYN={13} FIN={14}'
                  ' Attck=NULL Scan'.format(str(args[0]), str(args[1]), str(args[2]), str(args[3]), str(args[4]),
                                            str(args[5]), str(args[6]), str(args[7]), str(args[8]), str(args[9]),
                                            str(args[10]), str(args[11]), str(args[12]), str(args[13]),
                                            str(args[14])), file=fout)
        elif args[9] == 1 and args[11] == 1 and args[14] == 1:
            print('{0} Src_MAC={1} Dst_MAC={2} Src_IP={3} Dst_IP={4} Src_Port={5} Dst_Port={6} Seq={7} ACK_No={8}'
                  ' URG={9} ACK={10} PUSH={11} RST={12} SYN={13} FIN={14}'
                  ' Attck=XMAS Scan'.format(str(args[0]), str(args[1]), str(args[2]), str(args[3]), str(args[4]),
                                            str(args[5]), str(args[6]), str(args[7]), str(args[8]), str(args[9]),
                                            str(args[10]), str(args[11]), str(args[12]), str(args[13]),
                                            str(args[14])), file=fout)
        elif args[11] == 0 and args[14] == 1:
            print('{0} Src_MAC={1} Dst_MAC={2} Src_IP={3} Dst_IP={4} Src_Port={5} Dst_Port={6} Seq={7} ACK_No={8}'
                  ' URG={9} ACK={10} PUSH={11} RST={12} SYN={13} FIN={14}'
                  ' Attck=FIN Scan'.format(str(args[0]), str(args[1]), str(args[2]), str(args[3]), str(args[4]),
                                           str(args[5]), str(args[6]), str(args[7]), str(args[8]), str(args[9]),
                                           str(args[10]), str(args[11]), str(args[12]), str(args[13]),
                                           str(args[14])), file=fout)
    # Log YARA detection
    if proto == 'yara':
        print('{0} Sub_Type={1} Strings={2} Results={3} Attack=YARA'.format(str(args[0]), str(args[1]), str(args[2]),
                                                                            str(args[3])), file=fout)

    # Log port monitoring
    if proto == 'port':
        print('{0} Src_IP={1} Port_Number={2} Port_Name={3} Attack=Port_Traffic'.format(str(args[0]), str(args[1]),
                                                                                        str(args[2]),
                                                                                        str(args[3])), file=fout)

    fout.close()


def get_utc():
    utc_unformatted = datetime.datetime.utcnow().timestamp()
    utc_formatted = datetime.datetime.fromtimestamp(int(utc_unformatted)).strftime('%Y-%m-%d %H:%M:%S')
    return utc_formatted


# Get host local IP address
def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as msg:
        print("Socket could not be created. Error Code : " + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    try:
        s.connect(('8.8.8.8', 80))
    except:
        print('Cannot connect to 8.8.8.8 IP Address. Check your connection')
        curses.endwin()
        sys.exit()
    return s.getsockname()[0]
