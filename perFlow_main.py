from perFlow import *

if __name__ == '__main__':
    test = 1
    if (len(sys.argv) > 1):
        if (sys.argv[1] == "-a"):
            test = 0
        if (sys.argv[1] == "-m"):
            test = 2

    # Either parse a small test file or the large data set
    fName = ""
    if (test == 1):
        packetList = parser.read_test_tracefile()
        fName = "perFlow1"
    elif (test == 2):
        packetList = parser._parse_tracefile("trace_med")
        fName = "perFlow_med"
    else:
        packetList = parser.read_tracefile()
        fName = "perFlowStatistics"
        
    
    flowLst = FlowList()
    print("> Populating flow list")
    flowLst.populate(packetList)

    print("> Writing markdowns")
    # ============================ Markdowns ============================
    f = open(fName + ".md", "w")
    writeReportHeader(f)
    writeFlowCountTable(f, flowLst)
    writeStatesTable(f, flowLst)
    f.close()

    print("> Writing CDFs to plots/")
    # ============================ CDF Plots ============================
    initCDF('Flow Duration CDF', 'Duration of Flow (ms)', 'Fraction of Data')
    plotFlow(flowLst, Flow.getDuration)
    displayCDF(fName + "-duration")

    initCDF('Flow Size CDF - Packets', 'Number of packets', 'Fraction of Data')
    plotFlow(flowLst, Flow.getTotalPackets)
    displayCDF(fName + "-packets")

    initCDF('Flow Size CDF - Bytes', 'Flow Size (bytes)', 'Fraction of Data')
    plotFlow(flowLst, Flow.getTotalSize)
    displayCDF(fName + "-size")

    initCDF('Flow Size CDF - Overhead Ratio', 'Overhead Ratio', 'Fraction of Data')
    plotFlow(flowLst, Flow.getOverheadRatio, "TCP")
    displayCDF(fName + "-overhead")

    initCDF('Inter-Packet Arrival Time CDF', 'Inter-Arrival Time (ms)', 'Fraction of Data')
    plotFlow(flowLst, Flow.getInterArrivalTimes)
    displayCDF(fName + "-interarrival")

    print("Per-flow analysis complete.")

    # The flow list may utilize a large amount of memory, so Python may take a long time to exit.
    # This method exits the process immediately without performing cleanup.
    os._exit(0)
    