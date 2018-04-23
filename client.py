import socket
import sys
import threading
import time
import struct
from queue import *

def carry_around_add(a, b):
    ''' This is used for using the carry of the checksum in the actual 16 digits of check sum'''
    c = a + b
    return (c & 0xffff) + (c >> 16)


def check_check_sum(packet):
    ''' This is used for calculating the checksum for the passed packet'''
    packet = packet.decode('utf-8')
    sum = 0
    for i in range(0, len(packet), 2):
        if (i + 1) < len(packet):
            temp_sum = ord(packet[i]) + (ord(packet[i + 1]) << 8)
            sum = carry_around_add(temp_sum, sum)
    return sum & 0xffff

def form_packet(packet, seq, packet_type):
    '''This is for packing the packet with 32 bit sequence number, 16 bit check sum and 16 bit type information'''
    check_sum_value = check_check_sum(packet)
    packet_type = str_binary_to_i(packet_type)
    header_value = struct.pack('!LHH', int(seq), int(check_sum_value), int(packet_type))
    return header_value + packet


def extract_from_file(file, mss):
    '''This is used for extracting mss '''
    current_seq = 0
    packet = ''
    try:
        fileread = open(file, 'rb')
        read_mss_bytes = fileread.read(mss)
        while read_mss_bytes:
            packet_to_send.append(form_packet(read_mss_bytes, current_seq, packet_type_data_16_bits))
            read_mss_bytes = fileread.read(mss)
            current_seq += 1
        # packet_to_send.append(form_packet(packet, current_seq, packet_type_data_16_bits))
        packet = "0".encode('utf-8')
        packet_to_send.append(form_packet(packet, current_seq, fin_packet_type))
        fileread.close()
        global total_packets
        global track_packets
        total_packets = len(packet_to_send)
        # we have a packet tracker to track whether a packet is acknowledged or not
        track_packets = [False] * total_packets

    except (FileNotFoundError, IOError):
        print("Wrong file name or file path")
        exit(1)



# def receive_ACK(client_socket):
def rdt_send(client_socket, window_size, server_name, sever_port):
    '''This takes care of sending all the packets that are present in the packets to send list'''
    global packet_number_tracking
    global window_start
    global timestamp
    global resend_queue
    global retransmissions


    timestamp = [0.0]*total_packets
    last_packet_send = -1

    # This gets values added when packets in transit have not been acknowledged and their time surpasses the RTO

    while acks_received < total_packets-1:
        lock.acquire()
        #packet number tracking len is the number of packets that are currently in transit
        packet_number_tracking_len = len(packet_number_tracking)

        if (packet_number_tracking_len < window_size) and ((window_start + packet_number_tracking_len) < total_packets):
            #we will loop here and send all the packets in the window and wait for the acknowledgements

            # first resend all that are present in the resend queue starting from lowest to highest
            #initially the list will be empty there by not resending anything
            while not resend_queue.empty():
                i = resend_queue.get()
                if not track_packets[i]:
                    packet_to_be_sent = packet_to_send[i]
                    timestamp[i] = time.time()
                    send_packet(packet_to_be_sent)
                    packet_number_tracking.append(i)

            # new packets present in the window
            j = last_packet_send + 1
            temp = min(window_start + window_size, total_packets)
            while j < temp:
                if not track_packets[j]:
                    packet_to_be_sent = packet_to_send[j]
                    timestamp[j] = time.time()
                    send_packet(packet_to_be_sent)
                    packet_number_tracking.append(j)
                    last_packet_send = j
                j += 1

        # tracking all the ones that are in transit
        packet_number_tracking_len = len(packet_number_tracking)
        to_be_removed = []  # for removing packets in transit
        if packet_number_tracking_len > 0:
            # (time.time() - timestamp[window_start]) > RTO:
            for packet_number in packet_number_tracking:
                if track_packets[packet_number]:  # means it is acknowledged
                    to_be_removed.append(packet_number)


                elif (time.time() - timestamp[packet_number]) > RTO:
                    if not track_packets[packet_number]:
                        #print("Time out, Sequence number: " + str(packet_number))
                        resend_queue.put(packet_number)
                        retransmissions += 1
                        to_be_removed.append(packet_number)

        # finding the new window size depends on the resend values and the values in transit

        if len(to_be_removed) > 0:
            packet_number_tracking = remove_items_util(packet_number_tracking, to_be_removed)
            to_be_removed.clear()

        lock.release()


def  remove_items_util(a,b):
    return list(set(a)-set(b))


def receive_ACK(client_socket):
    '''This takes care of receiving the acknowledgements from the server for the sent paclets.
    This runs in parallel thread to the main thread, that runs the sending packets'''
    global packet_number_tracking
    global window_start
    global acks_received

    while acks_received < total_packets-1:
        packet_number_tracking_len = len(packet_number_tracking)
        if packet_number_tracking_len > 0:
            data = client_socket.recv(2048) #2048 IS ENOUGH FOR THE ACCNOWLEDGEMENTS
            lock.acquire()
            ack_number, zeroes_received, packet_type = decapsulate(data)
            if ack_number in packet_number_tracking:
                packet_number_tracking.remove(ack_number)

            if not zeroes_received == str_binary_to_i(zeros) or not packet_type == str_binary_to_i(packet_type_ack_16_bits):
                print("Invalid Acknowledgement, Sequence number = ", window_start)
                resend_queue.put(ack_number)
                track_packets[ack_number] = False
            else:
                if not track_packets[ack_number]:  # this is for non duplicate real acknowledgement
                    acks_received += 1
                    track_packets[ack_number] = True  # meaning acknowledgement is received for this packet
                    print("ack, ",acks_received)
                    # we can now evaluate the window start by looping from the current
                    #  window start up to window size values with track packets being true
                    i = window_start
                    end = min(i+n, total_packets)  # to avoid over running the total packets
                    while i < end and track_packets[i]:
                        i += 1
                        continue
                    window_start = i
            lock.release()

def send_packet(packet):
    global client_socket
    client_socket.sendto(packet, (server_name, server_port))

def decapsulate(packet):
    """ https://docs.python.org/2/library/struct.html """
    tcp_headers = struct.unpack('!LHH', packet[0:8]) # the tcp header information that we are passing are nine bytes - seq num, checksum and EOF message
    sequence_number = tcp_headers[0]
    zeroes = tcp_headers[1]
    packet_type = tcp_headers[2]
    return sequence_number, zeroes, packet_type

def str_binary_to_i(str):
    return int(str, 2)



if __name__ == "__main__":
    '''The main function where all the configurations happens'''
    client_host = socket.gethostname()
    client_ip = socket.gethostbyname(client_host)
    print("received host",client_ip)
    client_port = 60000
    packet_to_send = []
    track_packets = []
    packet_number_tracking = []
    timestamp = []
    window_start = 0
    lock = threading.Lock()
    total_packets = 0
    packet_type_data_16_bits = "0101010101010101"
    fin_packet_type = "1111111111111111"
    packet_type_ack_16_bits = "1010101010101010"
    zeros = "0000000000000000"
    retransmissions = 0
    acks_received = 0

    RTO = 0.1 # value in seconds
    if len(sys.argv) == 6 and sys.argv[1] and sys.argv[2] and sys.argv[1] and sys.argv[3] and sys.argv[4] and sys.argv[5]:
        server_name = sys.argv[1]
        server_port = int(sys.argv[2])
        file = sys.argv[3]
        n = int(sys.argv[4])
        mss = int(sys.argv[5])
        resend_queue = Queue(maxsize=n)
    else:
        raise ValueError("Please enter valid arguments in the order: server host name, server port, download file name, window size and MSS")

    print("Server name: " + str(server_name) + " and port " + str(server_port))
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.bind(('0.0.0.0', client_port))
    print("client running on IP " + str(client_ip) + " and port " + str(client_port))
    extract_from_file(file, mss)
    print("Total Packets present : "+str(total_packets))
    t = threading.Thread(target= receive_ACK, args= (client_socket,))
    t.start()
    start_time = time.time()
    rdt_send(client_socket, n, server_name, server_port)
    t.join()
    end_time = time.time()
    time_taken = end_time - start_time
    print("Time for sending and receiving Acknowledgements", str(time_taken))
    print("Retransmissions", str(retransmissions))
    client_socket.close()