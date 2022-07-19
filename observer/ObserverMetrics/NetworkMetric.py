import psutil
import socket
import time
from netifaces import interfaces, ifaddresses, AF_INET


def net_io_measures(seconds):
    """
    Network IO measures

    Assesses the network I/O operations for a time interval and returns a speed (MB or packets / seconds).

    Parameters:
    seconds (int): Time interval in seconds

    Returns:
    send_mega_bytes_sec (int): Number of total MB that the network have sent in the time interval
    recv_mega_bytes_sec (int): Number of total MB that the network have received in the time interval
    send_packets_speed (int): Number of packets that the network have sent in the time interval
    receive_packets_speed (int): Number of packets MB that the network have received in the time interval
    """
    # start measure
    start_time = time.time()
    net_io_counter = psutil.net_io_counters(True)

    start_sent_bytes = net_io_counter['eth0'][0]
    start_recv_bytes = net_io_counter['eth0'][1]
    start_sent_packets = net_io_counter['eth0'][2]
    start_recv_packets = net_io_counter['eth0'][3]

    # wait before next measure
    time.sleep(seconds)

    # end measure
    net_io_counter = psutil.net_io_counters(True)

    end_sent_bytes = net_io_counter['eth0'][0]
    end_recv_bytes = net_io_counter['eth0'][1]
    end_sent_packets = net_io_counter['eth0'][2]
    end_recv_packets = net_io_counter['eth0'][3]

    end_time = time.time()

    # calculations
    time_diff = end_time - start_time

    send_bytes_speed = (end_sent_bytes - start_sent_bytes) / time_diff
    receive_bytes_speed = (end_recv_bytes - start_recv_bytes) / time_diff
    send_packets_speed = (end_sent_packets - start_sent_packets) / time_diff
    receive_packets_speed = (end_recv_packets - start_recv_packets) / time_diff

    # conversions
    send_mega_bytes_sec = round(send_bytes_speed / (1024 ** 2), 2)
    recv_mega_bytes_sec = round(receive_bytes_speed / (1024 ** 2), 2)

    return (send_mega_bytes_sec, recv_mega_bytes_sec, send_packets_speed, receive_packets_speed)


def local_ip_address():
    """
    Local IP address

    Returns the local IP address that the system is using.

    Parameters:
    none

    Returns:
    s.getsockname()[0] (string): Local IP address
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


def print_interfaces_ip_addresses():
    """
    Network interfaces

    Prints a list of all network interfaces.

    Parameters:
    none

    Returns:
    none
    """
    for ifaceName in interfaces():
        addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr': 'No IP addr'}])]
        print('%s: %s' % (ifaceName, ', '.join(addresses)))


def tcp_measures():
    """
    TCP connections information

    Returns a list of list elements, containing information for all tcp connections: FD, lAddIP, lAddPort, rAddIP,
    rAddPort, status, PID

    Parameters:
    none

    Returns:
    (list): list of tcp connections with the following information: FD, lAddIP, lAddPort, rAddIP, rAddPort, status, PID.
    """
    connections = psutil.net_connections()
    tcp_connections = []

    for c in connections:
        fd = c[0]
        ladd_ip = c[3][0]
        ladd_port = c[3][1]
        try:
            radd_ip = c[4][0]
        except IndexError as e:
            radd_ip = None
        try:
            radd_port = c[4][1]
        except IndexError as e:
            radd_port = None

        status = c[5]
        pid = c[6]
        row = [fd, ladd_ip, ladd_port, radd_ip, radd_port, status, pid]
        tcp_connections.append(row)

    return tcp_connections
