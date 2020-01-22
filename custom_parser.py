# Script: custom_parser.py
# Desc: Used to hold parsers build specifically for pcacp analyser.
# Author: LiamOJ
# Last edit: 08/12/2019

import os
import re
import dpkt
import urllib.parse as url


def uri_parser(all_ip_list, uri_file_filter):
    """Use to filter out targeted file types from a list of IP objects"""
    
    uri_list = []

    # iterate through packets, checking for matching URIs
    for packet in all_ip_list:
        tcp = packet.data
        try:
            http = dpkt.http.Request(tcp.data)
            if http.method == "GET":
                uri = http.uri.lower()
                for file_type in uri_file_filter:
                    if file_type in uri:
                        if uri is not None:
                            uri_list.append(http.headers["host"] + uri[0:uri.find('?')])
                            # remove surplus host/uri text, little bit hacky
        except dpkt.UnpackError:
            continue
        except AttributeError:
            continue
        except TypeError:
            continue

    return uri_list


def uri_filename_parser(uri_list):
    """Pass in a list of URIs to return a dictionary of URI and filename"""
    
    uri_filename_dict = {}

    for uri in uri_list:
        uri_filename_dict[uri] = os.path.basename(url.urlparse(uri).path)

    return uri_filename_dict


def email_parser(tcp_data, ctrl_dict):
    """Use to apply the given regex to the targeted

    ports on the list of IP objects"""
    
    emails_set = set()

    for packet in tcp_data:
        try:
            if packet.sport in ctrl_dict["ports"] \
            or packet.dport in ctrl_dict["ports"]:
                email = re.findall(
                    ctrl_dict["regex"], packet.data.decode(ctrl_dict["code"])
                )
                if email:
                    emails_set.update(email)
        except UnicodeDecodeError:
            continue

    return emails_set


def main():
    pass


if __name__ == "__main__":
    main()
