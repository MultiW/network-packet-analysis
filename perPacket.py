import trace_parser as parser
from layer import Layer
import numpy as np
from matplotlib import pyplot as plt
import os


layer_names = {0:'Link', 2:'Network', 3:'Transport'}
packet_types = {0:{'Ethernet'},
                       2:{'IPv4', 'IPv6', 'ICMP', 'ARP'},
                       3:{'TCP', 'UDP'}}
layer_list = {} # dictionary of Layer objects

# ======================== Per-Packet Type Analysis ========================

def print_types_tables():
    for key in layer_list:
        layer = layer_list[key]
        print(layer.get_name())
        print(layer.generate_table())
        print()
        
def print_markdown_types_tables():
    for key in layer_list:
        layer = layer_list[key]
        print('**' + layer.get_name() + '**')
        print(layer.generate_markdown_table())
        print()

# ======================== Per-Packet Size Analysis ========================

def _list_all_packet_sizes():
    all_sizes = []
    for key in layer_list:
        layer = layer_list[key]
        sizes_dict = layer.get_packet_sizes_list()
        for key2 in sizes_dict:
            all_sizes += sizes_dict[key2]
    return all_sizes

def _list_packet_sizes(plot_packet):
    # search for given packet in layers
    for key in layer_list:
        layer = layer_list[key]
        packet_sizes = layer.get_packet_sizes_list()
        if plot_packet in packet_sizes:
            return packet_sizes[plot_packet]
    return []

def _generate_plot(data, name):
    x = np.sort(data)
    y = np.arange(1,len(x)+1) / len(x)
    plt.plot(x,y, label=name)

def _generate_cdf_graphs(add_graph_line, layer):
    plt.title('Packet Size CDF: ' + layer)
    plt.xlabel('Packet Size (Bytes)')
    plt.ylabel('Fraction of Data')
    add_graph_line()
    plt.xscale('log')
    plt.legend()
    try:
        plt.savefig("plots/perPacketStatistics-" + str(layer.lower()) + "-packetsize-log.png", dpi=300)
    except:
        os.makedirs("plots")
    plt.show()
        
def _add_all_packets_graph_line():
    all_sizes = _list_all_packet_sizes()
    _generate_plot(all_sizes, 'All packets')

def _add_non_packets_graph_line():
    # get IP packet sizes
    packet_sizes = layer_list[2].get_packet_sizes_list()
    data = []
    for name in packet_sizes:
        if name == 'IPv4' or name == 'IPv6':
            continue
        data += packet_sizes[name]
    
    _generate_plot(data, 'Non-IP')

def add_transport_layer_graph_lines():
    _add_all_packets_graph_line()
    plots = ['TCP', 'UDP']
    for plot in plots:
        data = []
        data = _list_packet_sizes(plot)
        _generate_plot(data, plot)

        
def add_network_layer_graph_lines():
    _add_all_packets_graph_line()
    plots = ['IPv4', 'IPv6']
    for plot in plots:
        data = []
        data = _list_packet_sizes(plot)
        _generate_plot(data, plot)
    _add_non_packets_graph_line()

def generate_cdf_graphs():
    _generate_cdf_graphs(add_network_layer_graph_lines, 'Network')
    _generate_cdf_graphs(add_transport_layer_graph_lines, 'Transport')

# ==================== Per-Packet Header Size Analysis ====================
def _list_header_sizes(plot_packet):
    # search for given packet in layers
    for key in layer_list:
        layer = layer_list[key]
        packet_sizes = layer.get_header_sizes_list()
        if plot_packet in packet_sizes:
            return packet_sizes[plot_packet]
    return []
    
def _add_header_graph_lines():
    plots = ['IPv4', 'IPv6', 'TCP', 'UDP']
    for plot in plots:
        data = []
        data = _list_header_sizes(plot)
        _generate_plot(data, plot)

def generate_cdf_header_graphs():
    plt.title('Packet Header Size CDF')
    plt.xlabel('Packet Size (Bytes)')
    plt.ylabel('Fraction of Data')
    _add_header_graph_lines()
    plt.legend()
    try:
        plt.savefig("plots/perPacketStatistics-headersize.png", dpi=300)
    except:
        os.makedirs("plots")
    plt.show()

# ========================== Trace File Analysis ==========================

def _init_layers_analysis():
    # Initialize layers analysis objects
    for layer_id in packet_types:
        layer = Layer(layer_names[layer_id], packet_types[layer_id])
        layer_list[layer_id] = layer

def _get_packet_name(pkt):
    name = pkt.name
    if name == 'IP':
        name += 'v' + str(pkt.version)
    return name

def _record_packet(pkt_layer, depth, packet_size):
    header_size = len(pkt_layer) - len(pkt_layer.payload)
    # Link layer
    if depth == 0:
        layer = layer_list[depth]
        layer.add_packet_occurrence('Ethernet', packet_size, header_size)
        return
    pkt_name = _get_packet_name(pkt_layer)
    layer = layer_list[depth]
    layer.add_packet_occurrence(pkt_name, packet_size, header_size)

def _compute_packet_size(packet):
    try:
        return len(packet) - len(packet.payload.payload) + packet.len
    except AttributeError:
        return len(packet)

def analyze_packets(packetList):
    _init_layers_analysis()
    
    # Analyze trace file
    for packet in packetList:
        packet_size = _compute_packet_size(packet)
        
        # Iterate each layer of packet
        pkt_layer = packet
        depth = 0
        while pkt_layer:
            pkt_name = _get_packet_name(pkt_layer)
            # record all link layer packets as 'Ethernet'
            if depth == 0:
                _record_packet(pkt_layer, depth, packet_size)
                if depth == 0 and pkt_name != 'Ethernet':
                    depth += 1 # this packet has no second link layer
            elif depth == 2:
                if pkt_name == 'IPv4' or pkt_name == 'IPv6':
                    # ICMP protocol
                    if pkt_name != 'IPv6' and pkt_layer.proto == 1:
                        _record_packet(pkt_layer.payload, depth, packet_size)
                        break # no transport layer in ICMP
                    # Record IP packet info
                    else:
                        _record_packet(pkt_layer, depth, packet_size)
                # Non-IP packet types
                else:
                    _record_packet(pkt_layer, depth, packet_size)
                    break # Don't record transport protocol for Non-IP packets
            elif depth == 3:
                if pkt_name == 'Raw':
                    break
                _record_packet(pkt_layer, depth, packet_size)
            
            # loop logic
            pkt_layer = pkt_layer.payload
            depth += 1

if __name__ == '__main__':
    # Parse trace data
#    packet_list = parser.read_test_tracefile()
    packet_list = parser.read_tracefile()
    
    # Analysis
    analyze_packets(packet_list);
    print_types_tables()
    print_markdown_types_tables()
    generate_cdf_graphs()
    generate_cdf_header_graphs()
    