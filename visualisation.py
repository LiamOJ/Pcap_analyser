# Script: visualisation.py
# Desc: Creates two visual aids for pcap data, a weight and directed graph and a line chart. Part of the pcap analyser. 
# Author: LiamOJ
# Last edit: 08/12/2019

import numpy as np
import matplotlib.pyplot as plt
import statistics as stat
import networkx as nx
import os
import itertools
import datetime

def graph_creation(ordered_list, ctrl_dict):
    """Generate a weighted (by line width), directed graph of IP source to destination

    Requires a list of nested tuples, noramlisation low and high

    and graph sizing variables."""

    weight_list = []
    graph_edges = []
    graph_nodes = []
    
    # Parse the list of nested tuples into a node/edge list and weight list
    for (src, dst), count_int in ordered_list[::-1]:
        weight_list.append(count_int)
        graph_add = (src, dst)
        graph_nodes.append(graph_add)

    # Normalise values in weight list for neatness of graph
    ranged_normalised_weights = [
        ctrl_dict["low"]
        + (
            ((count - min(weight_list)) * (ctrl_dict["high"] - ctrl_dict["low"]))
            / (max(weight_list) - min(weight_list))
        )
        for count in weight_list
    ]

    # ref: https://en.wikipedia.org/wiki/Feature_scaling#Rescaling_(min-max_normalization)
    # norm = a + (x - min(x)) * (b - a) / max(x) - min(x) where a, b are min-max values
    # Sorry it's from wikipedia.

    # Results in a list taken from a list of iterables of all ip addresses, done lazily. 
    graph_nodes_list = list((itertools.chain.from_iterable(graph_nodes)))

    # Create graph
    plt.ion()
    fig = plt.figure(2)
    fig.set_size_inches(ctrl_dict["x"], ctrl_dict["y"])
    H = nx.DiGraph()
    H.add_nodes_from(graph_nodes_list)
    H.add_edges_from(graph_nodes)
    pos = nx.circular_layout(H)
    nx.draw_networkx(
        H,
        pos,
        font_size=8,
        width=ranged_normalised_weights,
        edge_color="g",
        node_color="r",
    )
    plt.show()
    print(f"\n[!] Opening {ctrl_dict['graph']} ...")
    fig.savefig(os.path.join(ctrl_dict["save"], ctrl_dict["graph"]))


def line_chart_creator(ts_dict, ctrl_dict):
    """Makes a line chart of network activity from a TS dict according to interval

    period. It requires a dictionary of activity sorted by timestamp, interval

    length and line chart name."""
    
    times = []
    traffic = []

    # Create lists for chart, make dates human readable
    # Best not to assume dict is in time order
    earliest_key = min(ts_dict.keys())
    for time in range(len(ts_dict.keys())):
        times.append(datetime.datetime.fromtimestamp(earliest_key).strftime('%M:%S'))
        traffic.append(ts_dict[earliest_key])
        earliest_key += ctrl_dict['interval']
    # https://stackoverflow.com/questions/6706231/fetching-datetime-from-float-in-python

    mean = stat.mean(traffic)
    stdv = stat.stdev(traffic)

    # generate graph
    plt.ion()
    fig = plt.figure(1)
    fig.set_size_inches(ctrl_dict["x"], ctrl_dict["y"])
    plt.plot(times, traffic, "--")
    plt.xlabel(f"Time Interval: {ctrl_dict['interval']}(s)", fontsize=15)
    plt.ylabel("Packet Count", fontsize=15)
    plt.axhline(y=mean + 2 * stdv, xmin=0.0, xmax=1.0, color="r")
    plt.title("Network Activity", fontsize=18)
    plt.legend(["Packet Count", "High Traffic Line"])
    plt.grid(color="c", linestyle="-", linewidth=0.1)
    plt.show()
    fig.savefig(os.path.join(ctrl_dict["save"], ctrl_dict["line"]))
    print(f"\n[!] Opening {ctrl_dict['line']} ...")


def main():
    pass


if __name__ == "__main__":
    main()
