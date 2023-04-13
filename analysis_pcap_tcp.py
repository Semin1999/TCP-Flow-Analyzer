import dpkt
import socket


class TCP:
    def __init__(self, source_ip, source_port, dest_ip, dest_port, flag, window_size, seq_number, ack_number, flag_ack,
                 flag_push, flag_syn, flag_fin, time_size, time_start, time_stamp):
        self.source_ip = source_ip
        self.source_port = source_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.flags = flag
        self.window_size = window_size
        self.seq_number = seq_number
        self.ack_number = ack_number
        self.f_ack = flag_ack
        self.f_push = flag_push
        self.f_syn = flag_syn
        self.f_fin = flag_fin
        self.time_size = time_size
        self.time_start = time_start
        self.time_stamp = time_stamp
        self.receiver_arr = []


all_tcp = []
syn_tcp = []
ack_arr = []
receive_arr = []
flow_dictionary = {}
tt = 0
pcap_file = open('assignment2.pcap', 'rb')
pcap = dpkt.pcap.Reader(pcap_file)
k = 0

for time_stamp, buffer in pcap:

    packet = dpkt.ethernet.Ethernet(buffer)
    ip = packet.data
    tcp = ip.data
    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    src_port = tcp.sport
    dst_port = tcp.dport
    flags = tcp.flags
    win_size = tcp.win
    seq_num = tcp.seq
    ack_num = tcp.ack
    syn_time = 0
    fin_time = 0
    startTime = 0
    binary_flags = bin(flags)[2:]
    binary_flags = str(binary_flags).zfill(12)
    f_ack = binary_flags[7]
    f_push = binary_flags[8]
    f_syn = binary_flags[10]
    f_fin = binary_flags[11]

    ip_size = ((buffer[14] & 15) * 4)
    tcp_buffer = 14 + ip_size
    time_size = len(buffer) - tcp_buffer

    if f_syn == '1' and f_ack == '0':
        startTime = time_stamp
        flow_dictionary[TCP(src_ip, src_port, dst_ip, dst_port, flags, win_size, seq_num, ack_num, f_ack, f_push,
                            f_syn, f_fin, time_size, startTime, time_stamp)] = []
    if f_fin == '1' and f_ack == '0':
        endTime = time_stamp
        break
    else:
        for i in flow_dictionary:
            if i.source_ip == src_ip and i.source_port == src_port and i.dest_ip == dst_ip and i.dest_port == dst_port:
                ts = time_stamp
                ack_arr.append(tcp.ack)
                flow_dictionary[i].append(TCP(src_ip, src_port, dst_ip, dst_port, flags, win_size, tcp.seq, ack_num,
                                              f_ack, f_push, f_syn, f_fin, time_size, startTime,
                                              ts))
            if i.source_ip == dst_ip and i.source_port == dst_port and i.dest_ip == src_ip and i.dest_port == src_port:
                ts = time_stamp
                receive_arr.append(TCP(src_ip, src_port, dst_ip, dst_port, flags, win_size, tcp.seq, ack_num,
                                       f_ack, f_push, f_syn, f_fin, time_size, startTime,
                                       ts))
number = 1
time_out = 0
rtt_send = 0.0
rtt_receive = 0.0
print("\nPart A")
for i in flow_dictionary:
    total_time = 0
    print("=====================================================================================")
    print(f"Flow {number}")
    number = 1 + number
    print(f"source IP address: {flow_dictionary[i][0].source_ip}, source port: {flow_dictionary[i][0].source_port}")
    print(f"destination IP address: {flow_dictionary[i][0].dest_ip}, destination port:"
          f" {flow_dictionary[i][0].dest_port}")
    ds = 0
    length = len(flow_dictionary[i])
    for j in range(length):
        ds += flow_dictionary[i][j].time_size
    j = 1
    for k in range(2):
        senderTCP = flow_dictionary[i][j]
        sender_source_ip = senderTCP.source_ip
        sender_source_port = senderTCP.source_port
        sender_dst_ip = senderTCP.dest_ip
        sender_dst_port = senderTCP.dest_port

        flow_length = len(flow_dictionary[i]) - 1

        print(f"Transaction {k + 1} (Sender) -> [Seq no: {senderTCP.seq_number}, Ack no: {senderTCP.ack_number}, "
              f"Window size: {senderTCP.window_size}]")

        pcap_file = open('assignment2.pcap', 'rb')
        pcap = dpkt.pcap.Reader(pcap_file)
        if rtt_send == 0.0:
            rtt_send = flow_dictionary[i][1].time_stamp
        for time_stamp, buffer in pcap:
            packet = dpkt.ethernet.Ethernet(buffer)
            ip = packet.data
            tcp = ip.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            src_port = tcp.sport
            dst_port = tcp.dport
            binary_flags = bin(tcp.flags)[2:]
            binary_flags = str(binary_flags).zfill(12)
            f_ack = binary_flags[7]
            f_push = binary_flags[8]
            f_syn = binary_flags[10]
            f_fin = binary_flags[11]
            if sender_source_ip == dst_ip and sender_source_port == dst_port and sender_dst_ip == src_ip and \
                    sender_dst_port == src_port:
                if f_syn == '0':
                    receiverTCP_seq_number = tcp.seq
                    receiverTCP_ack_number = tcp.ack
                    receiverTCP_window_size = tcp.win
                    if rtt_receive == 0.0:
                        time_out += 1
                        rtt_receive = time_stamp
                    print(
                        f"\t\t\t  (Receiver) -> [Seq no: {receiverTCP_seq_number}, Ack no: {receiverTCP_ack_number}, "
                        f"Window size: {receiverTCP_window_size}]")
                    break
        j += 2
    print(
        f"Throughput: "
        f"{ds / (flow_dictionary[i][length - 1].time_stamp - flow_dictionary[i][0].time_start) / 1000000}Mbps")

print("\nPart B")
'''
Algorithm to get Congestion window size in flow
- slow start
    • Double cwnd every RTT
    • cwnd *= 2 / RTT
      When the slow start threshold is reached, start additive increase
    • Cwnd +=1 / packet received
'''
Ack3_Dup_count = 0

for i in flow_dictionary:
    print(f'=======================================================')
    rtt_1 = rtt_receive - rtt_send
    l = 1
    count = 0
    while l < len(flow_dictionary[i]) - 2:
        if flow_dictionary[i][l].ack_number == flow_dictionary[i][l + 1].ack_number:
            if flow_dictionary[i][l + 1].ack_number == flow_dictionary[i][l + 2].ack_number:
                count = count + 1
                l += 3
            else:
                l += 1
        else:
            l += 1
    print(f'3 Duplicate Ack number count: {count//3}')
    tss = rtt_1
    k = 0
    while k < 3:
        tss = tss + flow_dictionary[i][k].time_stamp
        k += 1
        tss = tss // 2
        rtt_1 += 1
        print(f'Congestion window size: {int(tss*2/100000 - count//3)}')
    print(f'time out retransmission: {time_out}')
    time_out = 0