# Script: geolocation.py
# Desc: Does geolocation of IP address destinations using geolite database. Part of pcap analyser. 
# Author: LiamOJ
# Last edit: 08/12/2019

import geoip2.database
import socket
import os
import simplekml


def geolocation(all_packets_ip_list, ctrl_dict):
    """Pass in an IP list, database and names to open

    Google Map with points and save. Plots only destination IPs."""
    
    unique_pkt_dst = []
    
    for ip in all_packets_ip_list:
        try:
            unique_pkt_dst.append(socket.inet_ntoa(ip.dst))
        except AttributeError:
            continue
    unique_pkt_dst_set = set(unique_pkt_dst)

    # read in database
    reader = geoip2.database.Reader(os.path.join(os.path.curdir, ctrl_dict["geo db"]))

    # define KML object
    kml = simplekml.Kml()

    # add points from list
    for line in unique_pkt_dst_set:
        try:
            response = reader.city(line.strip())
            location = str(response.city.name) + ", " + str(response.country.iso_code)
            kml.newpoint(
                name=location,
                coords=[(response.location.longitude, response.location.latitude)],
            )
        except geoip2.errors.AddressNotFoundError:
            pass

    # save as a file and print contents to stdout
    kml.save(os.path.join(ctrl_dict["save"], ctrl_dict["kml"]))
    print(f"\n[!] Opening {ctrl_dict['kml']} in default app (Google Earth)")
    # open google earth with points
    os.startfile(os.path.join(ctrl_dict["save"], ctrl_dict["kml"]))


def main():
    pass


if __name__ == "__main__":
    main()
