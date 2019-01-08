class Layer:
    """
    Instance variables
    self.layer_name: str
        name of this network layer
    self.total_packets: int
        total packets in this network layer
    self.total_bytes: int
        total size in bytes of all packets
    self.packet_types_counter: dict(str:int)
        tracks occurrence for each packet type
    self.packet_types: set(str)
        main packet types in this layer
    self.packet_sizes_list: dict(str:[])
        for every layer type, record list of packet sizes
    self.header_sizes_list: dict(str:[])
        for every layer type, record list packet header sizes
    self.other_packets: set(str)
        array of packet types other than main ones (ones in packet_types)
    """
    def __init__(self, layer_name, packet_types):
        # define instance variables
        self.layer_name = layer_name
        self.total_packets = 0
        self.total_bytes = 0
        self.packet_types_counter = {}
        self.packet_types = packet_types
        self.packet_sizes_list = {}
        self.header_sizes_list = {}
        self.other_packets = set()
        
        self.packet_types.add('Other')
        for t in self.packet_types:
            self.packet_types_counter[t] = 0
            self.packet_sizes_list[t] = []
            self.header_sizes_list[t] = []
    
    def add_packet_occurrence(self, packet_type, packet_size, header_size):
        """
        Parameters
        packet_type: str
        """
        self.total_packets += 1
        self.total_bytes += packet_size
        if packet_type in self.packet_types:
            self.packet_types_counter[packet_type] += 1
            self.packet_sizes_list[packet_type].append(packet_size)
            self.header_sizes_list[packet_type].append(header_size)
        else:
            self.packet_types_counter['Other'] += 1
            self.packet_sizes_list['Other'].append(packet_size)
            self.header_sizes_list['Other'].append(header_size)
            self.other_packets.add(packet_type)

    def generate_table(self):
        table = []
        table.append([' ', 'Count', 'Percentage', 'Bytes'])
        
        other_row = []
        for packet_type in self.packet_types:
            count = self.packet_types_counter[packet_type]
            percentage = float(count) / self.total_packets * 100
            type_sum = sum(self.packet_sizes_list[packet_type])
            row = [packet_type, count, percentage, type_sum]
            # hold the 'other' row to be appended last
            if (packet_type == 'Other'):
                other_row = row
                continue
            table.append(row)
        table.append(other_row)
            
        return table
    
    def generate_markdown_table(self):
        table = self.generate_table()
        
        markdown_str = ''        
        for i in range(len(table)):
            row = table[i]
            row_str = ''
            
            # display markdown-specific string
            if i == 1:
                row_str += '|'
                for _ in row:
                    row_str += '--|'
                row_str += '\n'
                
            # display each row of data
            row_str += '|'
            for value in row:
                row_str += str(value) + '|'
            row_str += '\n'
            
            markdown_str += row_str
            
        return markdown_str

    def get_other_packet_types(self):
        return self.other_packets

    def get_header_sizes_list(self):
        return self.header_sizes_list
    
    def get_packet_sizes_list(self):
        return self.packet_sizes_list

    def get_packet_types_counter(self):
        return self.packet_types_counter
    
    def get_name(self):
        return self.layer_name
    