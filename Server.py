import socket
import sys
import random
import struct
import threading
import time
import sys

def decapsulate(packet):
    ''' https://docs.python.org/2/library/struct.html '''
    tcp_headers = struct.unpack('!LHH', packet[0:8]) # the tcp header information that we are passing are nine bytes - seq num, checksum and EOF message
    sequence_number = tcp_headers[0]
    check_sum = tcp_headers[1]
    packet_type = tcp_headers[2]
    data = packet[8:] # data starts from the 64th bit ( 32 bits for sequence number, 16 bits for checksum, 16 bits for packet type )
    data = data.decode('utf-8')
    return sequence_number, check_sum, packet_type , data


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def check_check_sum(packet, check_sum_from_client):
    sum = 0
    for i in range(0, len(packet), 2):
        if (i + 1) < len(packet):
            temp_sum = ord(packet[i]) + (ord(packet[i + 1]) << 8)
            sum = carry_around_add(temp_sum, sum)
    return (~sum & 0xffff) & check_sum_from_client

def acknowledge_packet(server_socket, client_address, sequence_number,zeros,packet_type):
    ''' the acknowledge packet contains only the headers : 32 bit sequence number. 16 bits of zeros and 16 bits of ack packet type'''
    tcp_header = struct.pack("!LHH",sequence_number,str_binary_to_i(zeros),str_binary_to_i(packet_type))
    server_socket.sendto(tcp_header,client_address)

def str_binary_to_i(str):
    return int(str, 2)


def build_file(packet_dict, n, file_printer):
    for i in range(n):
        if i in packet_dict:
            file_printer.write(packet_dict[i])


def time_wait_thread():
    '''This makes the server to wait for all the incoming requests after getting the fin packet
        This is as per the TCP protocol'''
    time.sleep(RTT*2)
    global flag
    flag = False
    build_file(packets_received, last_packet, file_printer)
    file_printer.close()
    server_socket.close()
    sys.exit()



if __name__ == '__main__':
    CLIENT_PORT = 60000
    HOST_NAME = '0.0.0.0'
    packet_type_data_16_bits = "0101010101010101"
    packet_type_ack_16_bits = "1010101010101010"
    zeros = "0000000000000000"
    fin_16_bits = '1111111111111111'
    packets_received = {}
    last_packet=0
    RTT = 0.100
    time_wait = threading.Thread(target= time_wait_thread)
    SERVER_PORT = int(sys.argv[1])
    FILE_LOC = sys.argv[2]
    LOSS_PROBABILITY = float(sys.argv[3])
    in_transfer = True
    flag = True
    time_wait_not_started = True
    file_printer = open(FILE_LOC, "w")
    # this step connects to a socket with UDP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST_NAME,SERVER_PORT))
    print("Server started and is listening at port : ",SERVER_PORT)
    while flag:
        data, addr = server_socket.recvfrom(2048)
        client_host_name = addr[0]
        sequence_number, checksum, packet_type, data = decapsulate(data)

        if check_check_sum(data,checksum) == 0 :
            # Check check sum will return 0 only if there is not issues in the checksum of the computed
            if random.random() < LOSS_PROBABILITY:
                # the packet has to be dropped
                print('Packet loss, sequence number = ', str(sequence_number))
                continue

            if packet_type == str_binary_to_i(fin_16_bits):
                # sending the last acknowledgement
                acknowledge_packet(server_socket, (client_host_name, CLIENT_PORT), sequence_number, zeros, packet_type_ack_16_bits)
                #acknowledging again for reliability
                acknowledge_packet(server_socket, (client_host_name, CLIENT_PORT), sequence_number, zeros, packet_type_ack_16_bits)
                last_packet = sequence_number
                print("Last packet received")
                if time_wait_not_started:
                    time_wait_not_started = False
                    time_wait.start()
                continue



            if not packet_type == str_binary_to_i(packet_type_data_16_bits):
                print("received packet type = ", str(packet_type))
                print("received data ", data)
                print("Packet type not supported")
                server_socket.close()
                break

            if not int(sequence_number) in packets_received:
                packets_received[int(sequence_number)] = data

            acknowledge_packet(server_socket, (client_host_name,CLIENT_PORT), sequence_number, zeros, packet_type_ack_16_bits)



        else:
            print('Improper Checksum, sequence number = ', str(sequence_number))



            
    build_file(packets_received, last_packet, file_printer)
    file_printer.close()
    server_socket.close()