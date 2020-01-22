# Script: pcap_alyser.py
# Desc: Takes in and does basic analysis on a pcap file 
# Author: LiamOJ
# Last edit: 08/12/2019

import dpkt
import re
import os
import json
import sys
import visualisation
import custom_parser
import dpkt_packet_manipulation
import geolocation


def directory_handling(save_directory):
    """Pass in a directory name to create (or clear if it already exists)

    This will always create it in the current working directory"""
    
    if os.path.exists(save_directory):
        for dirpath, dirname, filenames in os.walk(save_directory):
            for filename in filenames:
                os.remove(os.path.join(dirpath, filename))
    else:
        os.mkdir(save_directory)


def main():
    # Hardcoded filtering controls
    targeted_ports = [110, 995, 993, 2525, 1689, 587, 25, 143]
    uri_file_filter = [".jpg", ".gif", ".png", ".jpeg"]
    targeted_regex = re.compile(
        r"(TO:\s<([-\w\.]*[-\w\.]+@[\w-]+\.\w+[\.?[\w]*]*)>)|(FROM:\s<([-\w\.]*[-\w\.]+@[\w-]+\.\w+[\.?[\w]*]*)>)"
    )
    emails_print_dict = {"TO": [], "FROM": []}
    ip_protocols = {"UDP": 17, "TCP": 6, "IGMP": 2}
    email_parser_pdu = "TCP"
    decoding = "UTF-8"

    # Hardcoded file controls
    save_folder_name = "40405608_coursework"  # bottom 4 files will be saved here
    geoip_db = "GeoLite2-City.mmdb"  # will look in cwd
    graph_name = "pcap_graph.png"
    json_file_name = "src_dst_ips.json"
    line_chart_name = "pcap_line_chart.png"
    kml_name = "pcap.kml"

    # Hardcoded display controls
    edge_low = 0.4
    edge_high = 4  # normalisation range
    interval_length = 20  # controls time interval
    tab_size_for_display = 20  # modify to resize (most) terminal output
    x_axis_in_inches = 12
    y_axis_in_inches = 8 # Changes size of graph and line chart

    # File to use
    pcapfile = "evidence-packet-analysis.pcap"
    # pcapfile = 'evidence01.pcap'
    # pcapfile = 'filtered3.pcap'
    # pcapfile = 'filtered4.pcap'
    # pcapfile = 'googleWeb.pcap'
    # pcapfile = 'packet_ip_ub.pcap'
    # pcapfile = 'email_cc2.pcap'
    # pcapfile = 'smtp.pcap'

    # creates subdirectory with relative addressing
    save_directory = os.path.join(os.curdir, save_folder_name)
    directory_handling(save_directory)
    print(f'\n[!] Directory {save_folder_name} created.')

    # Controller dictionary, used to pass in multiple variables at once
    ctrl_dict = {
        "ports": targeted_ports,
        "file filter": uri_file_filter,
        "regex": targeted_regex,
        "email print": emails_print_dict,
        "protos": ip_protocols,
        "pdu": email_parser_pdu,
        "code": decoding,
        "low": edge_low,
        "high": edge_high,
        "interval": interval_length,
        "x": x_axis_in_inches,
        "y": y_axis_in_inches,
        "save": save_directory,
        "geo db": geoip_db,
        "graph": graph_name,
        "json": json_file_name,
        "line": line_chart_name,
        "kml": kml_name,
    }

    # Lists/dicts for storing requirements.
    all_packets_ip_list = []
    all_packets_ts_list = []
    json_dict = {}

    # Open pcap file
    print(f"\n[!] Reading in {pcapfile}")
    try:
        file = open(pcapfile, "rb")
    except FileNotFoundError as fi_er:
        print(
            f"Exception({fi_er.__class__.__name__}) : {fi_er}", file=sys.stderr
            )
        sys.exit()

    # Use dpkt class to read in file object
    pcap = dpkt.pcap.Reader(file)
    print(f"\n[!] File {pcapfile} read in ")

    # Read file into data structures
    for ts, buf in pcap:

        ip = dpkt.ethernet.Ethernet(buf).data

        all_packets_ip_list.append(ip)
        all_packets_ts_list.append(ts)

    file.close()

    print(f"\n[!] File {pcapfile} parsed and closed")
    
    print("\n[!] Building protocol summary data")

    # Build and print IP packet segment type data
    print("\u0332".join("\nData Protocol Summary"))
    print(
        "Data Type \t Count \t Mean Len \t First TS \t Last TS".expandtabs(
            tab_size_for_display
        )
    )
    # taken from https://stackoverflow.com/questions/10623727/python-spacing-and-aligning-strings  
    for protocol in ip_protocols.keys():
        total, average, first, last = dpkt_packet_manipulation.protocol_summary(
            ip_protocols[protocol], all_packets_ip_list, all_packets_ts_list
        )
        print(
            f"{protocol} \t {total} \t {average} \t {first} \t {last}".expandtabs(
                tab_size_for_display
            )
        )

    # Build and print unique emails
    print("\n[!] Parsing for emails")
    print("\u0332".join("\nUnique Emails Found:"))

    # Filters the packet list for desired PDU (TCP)
    tcp_list = [
        packet.data
        for packet in list(
            filter(
                lambda packet: (
                    type(packet) is not dpkt.arp.ARP
                    and packet.p == ip_protocols[email_parser_pdu]
                ),
                all_packets_ip_list,
            )
        )
    ]

    # Send TCP list with specifications to parser
    unique_emails = custom_parser.email_parser(tcp_list, ctrl_dict)

    # Organise and append emails to list for next phase
    # Slicing number is based on 4-part regex capture
    for email in unique_emails:
        if any("TO: " in string for string in email):
            emails_print_dict["TO"].append(email[1])
        elif any("FROM: " in string for string in email):
            emails_print_dict["FROM"].append(email[3])

    # Print unique emails
    for key in emails_print_dict.keys():
        print(f"\u0332".join(f"Emails {key}"))
        for item in emails_print_dict[key]:
            print(item)

    # Build URI output and print
    print("\n[!] Building filename and URI data")
    uri_list = custom_parser.uri_parser(all_packets_ip_list, uri_file_filter)
    print("\u0332".join("\nURIs and Filenames Found:"))
    print("{:50} {:50}".format("Filename", "Full URI"))
    uri_dict = custom_parser.uri_filename_parser(uri_list)
    for uri in uri_dict:
        print("{:50} {:50}".format(uri_dict[uri], uri))
    # taken from https://stackoverflow.com/questions/33323715/python-evenly-space-output-data-with-varying-string-lengths

    print("\n[!] Building source to destination and count data")
    
    # Getting dict of src to dst IPs with counts
    unordered_dict = dpkt_packet_manipulation.src_and_dst(all_packets_ip_list)

    # Ordering that dict by values
    ordered_list = sorted(unordered_dict.items(), key=lambda t: t[1])
    # https://stackoverflow.com/questions/613183/how-do-i-sort-a-dictionary-by-value

    # Display IP src, dst and count
    print("\u0332".join("\nSource to Destination IPs and Counts:"))
    
    print("Source IP \t Destination IP \t Count".expandtabs(tab_size_for_display))
    for line in ordered_list[::-1]:
        ip_pair, count_int = line
        json_dict[''.join(ip_pair[0]) + " - > " + ''.join(ip_pair[1])] = count_int
        # JSON code put here to avoid unneeded/repeatitive code iteration
        print(
            f"{ip_pair[0]} \t {ip_pair[1]}\t {count_int}".expandtabs(
                tab_size_for_display
            )
        )

    # Line chart
    visualisation.line_chart_creator(
        dpkt_packet_manipulation.ts_dict_creator(
            all_packets_ts_list,
            interval_length),
        ctrl_dict,
    )
    print(
        f"\n[!] File {line_chart_name} saved to {os.path.join(os.getcwd(), save_folder_name)}"
    )
    
    # Networkx graph
    try:
        visualisation.graph_creation(ordered_list, ctrl_dict)
        print(
            f"\n[!] File {graph_name} saved to {os.path.join(os.getcwd(), save_folder_name)}"
        )
    except ZeroDivisionError as graph_err:
        print(f"\n[!] Exception({graph_err.__class__.__name__}) : {graph_err} (graph not generated)", file=sys.stderr)
    
    # JSON file creation
    with open(os.path.join(save_directory, json_file_name), "w") as json_file:
        json.dump(json_dict, json_file, indent=4)
    print(
        f"\n[!] File {json_file_name} saved to {os.path.join(os.getcwd(), save_folder_name)}"
    )

    # Geolocation from IPs
    geolocation.geolocation(all_packets_ip_list, ctrl_dict)
    print(f"\n[!] File {kml_name} saved to {os.path.join(os.getcwd(), save_folder_name)}")

    print("\n[!] All processes complete...")


if __name__ == "__main__":
    main()
