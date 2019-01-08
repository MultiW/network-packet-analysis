from perFlow import *

if __name__ == '__main__':
    test = 0
    if (len(sys.argv) > 1):
        if (sys.argv[1] == "-a"):
            test = 0
        if (sys.argv[1] == "-m"):
            test = 2

    # Either parse a small test file or the large data set
    fName = ""
    if (test == 1):
        packetList = parser.read_test_tracefile()
        fName = "RTT_small"
    elif (test == 2):
        packetList = parser._parse_tracefile("trace_med")
        fName = "RTT_med"
    else:
        packetList = parser.read_tracefile()
        fName = "RTTStatistics"
    
    flowLst = FlowList()
    flowLst.populate(packetList)

    # =============================== RTT ===============================
    print('Finding Top 3 Flows')
    uniqueTcpFlows = flowLst.uniqueFlows["TCP"]
    topPacketFlows, topPacketMetadata = getTopThreePacketsFlows(uniqueTcpFlows, getMostPacketsFlows)
    topBytesFlows, topBytesMetadata = getTopThreePacketsFlows(uniqueTcpFlows, getMostBytesFlows)
    topDurationFlows, topDurationMetadata = getTopThreePacketsFlows(uniqueTcpFlows, getLongestDurationFlows)
    topConnectionsPairs, topConnectionsPairsCounts = getTopThreeTcpConnectionFlows(uniqueTcpFlows)
    
    print('Drawing RTT Plots')
    displayRttPlots(topPacketFlows, 'Top TCP Flows In Terms of Packet Number', topPacketMetadata, 'packets', fName+'TopPacket')
    displayRttPlots(topBytesFlows, 'Top TCP Flows In Terms of Total Bytes', topBytesMetadata, 'Bytes', fName+'TopBytes')
    displayRttPlots(topDurationFlows, 'Top TCP Flows In Terms of Duration', topDurationMetadata, 'ms',fName+'TopDuration')
    displayRttIpPairs(topConnectionsPairs, topConnectionsPairsCounts, fName+'TopConnections')