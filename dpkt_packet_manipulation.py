# Script: dpkt_packet_manipulation.py
# Desc: Used to create and manipulate basic data structures relating to pcap
# analysis in conjuction with the dpkt module. Part of the pcap analyser. 
# Author: LiamOJ
# Last edit: 08/12/2019

import dpkt
import socket
import numpy as np
import statistics as stat
import time


def ts_dict_creator(time_stamp_list, interval_length):
    """Generates a timestamp dict from a timestamp list and

    passed interval time length"""

    # Build ts interval dict, 0 for values.
    # Returns numpy array.
    ts_dict = {
        key: 0
        for key in np.arange(
            time_stamp_list[0],
            time_stamp_list[-1] + interval_length,
            interval_length
        )
    }

    # get first time stamp
    first_ts = time_stamp_list[0]

    # populate ts_dict with counts
    # does not assume dict is ordered
    for stamp in range(len(ts_dict)):
        for ts in time_stamp_list:
            if ts >= first_ts and ts < first_ts + interval_length:
                ts_dict[first_ts] += 1
        first_ts += interval_length

    return ts_dict


def src_and_dst(full_ip_list):
    """Use to make a dictionary of source to destination IPs

    with counts from a packet list"""
    
    ip_src_and_dst_dict = {}

    for ip in full_ip_list:
        try:
            # Extract ip dst/src
            ip_src = socket.inet_ntoa(ip.src)
            ip_dst = socket.inet_ntoa(ip.dst)

            # Dictionary for counting
            key = (ip_src, ip_dst)

            if key not in ip_src_and_dst_dict:
                ip_src_and_dst_dict[key] = 1
            else:
                ip_src_and_dst_dict[key] += 1
        except AttributeError:
            continue

    return ip_src_and_dst_dict


def protocol_check(protocol, packet):
    """Use to check if a given packet matches a given protocol"""

    return type(packet) is not dpkt.arp.ARP and packet.p == protocol


def protocol_summary(protocol, all_packets_ip_list, all_packets_ts_list):
    """Give the protocol, IP list and TS list in order

    to return a summary of the given protocol"""

    # returns list populated with true/false depending on protocol check
    protocol_map_as_list = [
        protocol_check(protocol, packet) for packet in all_packets_ip_list
    ]

    # returns sub-list of packets of specific protcol 
    packet_sub_list = [
        packet for packet in all_packets_ip_list if protocol_check(
            protocol,
            packet
            )
    ]

    # Retrieve indices of first and last true
    try:
        time_stamp_indice = protocol_map_as_list.index(True)
    except ValueError:
        return 0, 0, "N/A", "N/A"
    
    time_stamp_rev_indice = (
        len(protocol_map_as_list) - protocol_map_as_list[::-1].index(True) - 1
    )
    total = len(packet_sub_list)
    average = round(stat.mean(
        [sub_packet.len for sub_packet in packet_sub_list]), 0)
    first = time.strftime(
        "%H:%M:%S", time.localtime(all_packets_ts_list[time_stamp_indice])
    )
    last = time.strftime(
        "%H:%M:%S", time.localtime(all_packets_ts_list[time_stamp_rev_indice])
    )

    return [total, average, first, last]


def main():
    pass


if __name__ == "__main__":
    main()
