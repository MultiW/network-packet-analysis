from scapy.all import rdpcap

TRACE_NUMBER = ((1003142663 + 1003424225) % 20) + 1 # 9


def read_tracefile():
    return _parse_tracefile('univ1_pt' + str(TRACE_NUMBER))

def read_test_tracefile():
    return _parse_tracefile('trace1')

def _parse_tracefile(path):
	print("> Parsing '" + path +"'")
	return rdpcap(path)