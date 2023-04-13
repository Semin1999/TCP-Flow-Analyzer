# TCP-Flow-Analyzer
Analyze the TCP flow in pcap file about Source IP address, source port, destination IP address, destination port ,attribute information such as sequence number of transmitted packet, arc number of received packet, and window size, total transmission size and rate of TCP flow, number of timeouts and retransmissions that occurred during transmission, efficiency analysis of TCP congestion control algorithm through congestion window size analysis


# Read me: Run Instruction
1. Install python. 
2. Install dpkt for import dpkt. 
3. Running on over python 3.8 version. 
4. This program can run through the command line. 
5. Check the file path of your ‘.pcap’ file is same directory with analysis_pcap_tcp.py 
6. If you want to run with other pcap file, you can change file name in line 32. pcap_file = open('assignment2.pcap', 'rb') 
*Change assignment2 to what you want. 
7. Example to run code : C: \path of assignment2.pcap and analysis_pcap_tcp.py \ python analysis_pcap_tcp.py


# Explanation of my Code
The analysis_pcap_tcp program reads and analyzes a given PCAP file to characterize TCP flows. It opens the PCAP file in binary format and reads the file using the dpkt library. After analyzing the given file, it prints the answers to Part A and Part B. 

Part A: To determine the number of TCP flows in the tcp flow, it checked how many TCP flows started from the sender with a syn and successfully connected with response syn and ack. Using the methods of dpkt, it was able to obtain source port, source IP address, destination port, and destination IP address in the IP protocol and TCP protocol. It grouped them by using this information. After the TCP connection was established, meaning the receiver sent ack and syn, it printed the first two transactions based on the information obtained from the parsing. It differentiated flows using the dictionary data structure.

Part B: It calculated the RTT of the initial transaction to obtain the estimated time for 1_RTT. (Note that the estimated value for Part B may vary as the RTT time may vary.) The congestion window size (cwnd) can be estimated for each RTT. It checked how many packets there were for the sender and receiver in the transaction. Loss is calculated by iterating through the list of flows in the dictionary value and calculating the difference in sequence numbers. If there is an error in the sequence number, it assumes there is loss (if the current received sequence number - the first sequence number is less than the current peer sequence number, it means there is loss). If the same ACK value is repeated three times in a row within a flow, it adds the value of "duplicate" for ACK duplicate.
