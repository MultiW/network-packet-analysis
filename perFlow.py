import trace_parser as parser
import numpy as np
import matplotlib
from matplotlib import pyplot as plt
from scapy.all import *

from flow import *
import sys, os

# This 'constant' is used as a filter flag when plotting;
#   also used as the label name on the plot
PLOT_ALL = "All Flows"

global fig, ax

# ============================ Report/CDF Functions ============================
def writeReportHeader(file):
    file.write("# RTT Estimation in the Real World\n")
    file.write("*Xin Wang Wang and James Huynh • 25 November 2018*\n")
    file.write("## Analysis\n")
    file.write("### Per-Flow Statistics\n")

def writeFlowCountTable(f, flowLst):
    f.write("#### Flow Type Count\n")
    f.write("||Count|Percentage|Bytes|\n")
    f.write("|--|--|--|--|\n")

    tcpCount = flowLst.count["TCP"]
    tcpBytes = flowLst.getTotalBytes("TCP")
    udpCount = flowLst.count["UDP"]
    udpBytes = flowLst.getTotalBytes("UDP")

    percent = float(tcpCount) / (tcpCount + udpCount + 0.0000001)
    f.write("|TCP|" + str(tcpCount) + "|" + "{:.1%}".format(percent) + "|" + str(tcpBytes) + "|\n")
    percent = float(udpCount) / (tcpCount + udpCount + 0.0000001)
    f.write("|UDP|" + str(udpCount) + "|" + "{:.1%}".format(percent) + "|" + str(udpBytes) + "|\n")

def writeStatesTable(f, flowLst):
    states = {"Request": 0,"Reset": 0,"Finished": 0,"Ongoing": 0,"Failed": 0}
    for flow in flowLst.uniqueFlows["TCP"]:
        if (flow.isValid()):
            states[flow.getState()] += 1

    f.write("#### TCP Flow States\n")

    row1 = "|"
    row2 = "|"
    for key, val in states.items():
        row1 += key + "|"
        row2 += str(val) + "|"

    f.write(row1 + "\n")
    f.write("|--|--|--|--|--|\n")
    f.write(row2 + "\n")

def initCDF(title, xlabel, ylabel):
    global fig, ax
    fig, ax = plt.subplots()
    plt.title(title)
    plt.subplots_adjust(bottom=0.15)
    plt.xlabel(xlabel, labelpad=10)
    plt.ylabel(ylabel, labelpad=10)
    plt.grid(linestyle="dashed", alpha=0.75)

def plotCDF(data, label):
    x = np.sort(data)
    y = np.arange(1, len(x)+1) / len(x)
    ax.plot(x, y, label=label)

def displayCDF(name):
    ax.legend()
    try:
        fig.savefig("plots/" + name + ".png", dpi=300)
    except:
        os.makedirs("plots")

    ax.set_xscale('log')
    try:
        fig.savefig("plots/" + name + "-log.png", dpi=300)
    except:
        os.makedirs("plots")

def plotFlow(flowLst, flowFunction, filterType=["TCP", "UDP", PLOT_ALL]):
    data = []
    for typ, lst in flowLst.uniqueFlows.items():
        if not (typ in filterType):
            continue
        localData = []
        for flow in lst:
            if (flow.isValid()):
                t = flowFunction(flow)
                try:
                    localData.extend(t)
                    if (PLOT_ALL in filterType):
                        data.extend(t)
                except:
                    localData.append(t)
                    if (PLOT_ALL in filterType):
                        data.append(t)

        plotCDF(localData, typ)

    if (PLOT_ALL in filterType):
        plotCDF(data, PLOT_ALL)

# ====================== Get Top 3 Flows ======================
def getMostPacketsFlows(flowArray, excludeIndex):
    mostPacketFlow = None
    mostPacketCount = -1
    mostPacketIndex = -1
    for i in range(len(flowArray)):
        if i in excludeIndex:
            continue
        flow = flowArray[i]
        pktCount = len(flow.packets)
        # initialize most packets attributes
        # or update flow with most packets
        if mostPacketCount == -1 or pktCount > mostPacketCount:
            mostPacketFlow = flow
            mostPacketCount = pktCount
            mostPacketIndex = i
    return mostPacketFlow, mostPacketCount, mostPacketIndex

def getMostBytesFlows(flowArray, excludeIndex):
    mostBytesFlow = None
    mostBytesCount = -1
    mostBytesIndex = -1
    for i in range(len(flowArray)):
        if i in excludeIndex:
            continue
        flow = flowArray[i]
        bytesCount = flow.totalSize
        # initialize most bytes attributes
        # or update flow with most bytes
        if mostBytesCount == -1 or bytesCount > mostBytesCount:
            mostBytesFlow = flow
            mostBytesCount = bytesCount
            mostBytesIndex = i
    return mostBytesFlow, mostBytesCount, mostBytesIndex

def getLongestDurationFlows(flowArray, excludeIndex):
    longestFlow = None
    longestDuration = -1
    longestDurationIndex = -1
    for i in range(len(flowArray)):
        if i in excludeIndex:
            continue
        flow = flowArray[i]
        duration = flow.lastArrival - flow.firstArrival
        # initialize longest duration attributes
        # or update flow with longest duration
        if longestDuration == -1 or duration > longestDuration:
            longestFlow = flow
            longestDuration = duration
            longestDurationIndex = i
    return longestFlow, longestDuration, longestDurationIndex

def getTopThreePacketsFlows(flowArray, getTopFunction):
    topFlowsMetadata = []
    topThree = []
    topThreeIndices = []
    for _ in range(3):
        flow, metadata, index = getTopFunction(flowArray, topThreeIndices)
        topThree.append(flow)
        topThreeIndices.append(index)
        topFlowsMetadata.append(metadata)
    return topThree, topFlowsMetadata

def _generateIpPairConnectionCounts(flowArray):
    # (IP1, IP2) -> count
    ipPairConnectionsCount = {}
    # (IP1, IP2) -> list(Flow)
    ipPairConnectionsFlows = {}
    for flow in flowArray:
        key = (flow.nodes[0][0], flow.nodes[1][0])
        key2 = (flow.nodes[1][0], flow.nodes[0][0])
        # if host pair exists
        if key in ipPairConnectionsCount:
            ipPairConnectionsCount[key] += 1
            ipPairConnectionsFlows[key].append(flow)
        # if host pair exists
        elif key2 in ipPairConnectionsCount:
            ipPairConnectionsCount[key2] += 1
            ipPairConnectionsFlows[key2].append(flow)
        # init new host pair
        else:
            ipPairConnectionsCount[key] = 1
            ipPairConnectionsFlows[key] = [flow]
    return ipPairConnectionsCount, ipPairConnectionsFlows

def _getMostTcpHosts(ipPairConnectionsCount, excludePairs):
    mostConnectionPair = None
    mostConnectionCount = -1
    for pair in ipPairConnectionsCount:
        if pair in excludePairs:
            continue
        connectionCount = ipPairConnectionsCount[pair]
        # initialize most connection attributes
        # or update pair with most connections
        if mostConnectionCount == -1 or connectionCount > mostConnectionCount:
            mostConnectionPair = pair
            mostConnectionCount = connectionCount
    return mostConnectionPair, mostConnectionCount

def getTopThreeTcpConnectionFlows(flowArray):
    ipPairConnectionsCount, ipPairConnectionsFlows = _generateIpPairConnectionCounts(flowArray)
    topThreePairs = []
    topThreeFlows = [] # ((IP1,IP2), list(Flow))
    topThreeCounts = []
    for _ in range(3):
        pair, count = _getMostTcpHosts(ipPairConnectionsCount, topThreePairs)
        topThreePairs.append(pair)
        topThreeFlows.append((pair, ipPairConnectionsFlows[pair]))
        topThreeCounts.append(count)
    return topThreeFlows, topThreeCounts


# ==================== RTT Helper Functions ====================
def initSubplot(title, xlabel, ylabel):
    global fig, ax
    fig, ax = plt.subplots()
    plt.title(title)
    plt.subplots_adjust(bottom=0.15)
    plt.xlabel(xlabel, labelpad=10)
    plt.ylabel(ylabel, labelpad=10)
    plt.grid(linestyle="dashed", alpha=0.75)
    
def savePlot(name):
    try:
        fig.savefig("plots/" + name + ".png", dpi=300)
    except:
        os.makedirs("plots")

    ax.set_yscale('log')
    try:
        fig.savefig("plots/" + name + "-log.png", dpi=300)
    except:
        os.makedirs("plots")

def _getPlotData(flow, packetPairs):
    rtt_data = []
    srtt_data = []
    time_data = []
    srtt = -1
    for key in packetPairs:
        send_pkt = flow.packets[key][0]
        # this packet didn't receive an acknowledgement
        if packetPairs[key] == -1:
            continue
        ack_pkt = flow.packets[packetPairs[key]][0]
        # generate rtt, srtt, and time data
        rtt = ack_pkt.time - send_pkt.time
        if srtt == -1:
            srtt = rtt
        else:
            alpha = float(1)/8
            srtt = (1 - alpha) * srtt + alpha * rtt
        time = send_pkt.time
        # add data
        rtt_data.append(rtt)
        srtt_data.append(srtt)
        time_data.append(time)
    return rtt_data, srtt_data, time_data
    
def displayRttPlots(flows, title, metadata, unit, filename):
    for i in range(len(flows)):
        flow = flows[i]
        value = metadata[i]
        # generate plot data
        packetPairs = flow.getRttPacketPairs()
        rtt_data, srtt_data, time_data = _getPlotData(flow, packetPairs)
        
        # plot
        initSubplot(title + ' (' + str(value) + ' ' + unit + ')', 'time (ms)', 'RTT (ms)')
        ax.plot(time_data, rtt_data, label='RTT')
        ax.plot(time_data, srtt_data, label='Estimated RTT')
        ax.legend()
        savePlot(filename+str(i))
        plt.show()

def displayRttIpPairs(topConnectionsPairs, topConnectionsPairsCounts, filename):
    for i in range(len(topConnectionsPairs)):
        tup = topConnectionsPairs[i]
        flows = tup[1]
        count = topConnectionsPairsCounts[i]
        # generate plot data
        med_srtt = []
        med_time_data = []
        for flow in flows:
            packetPairs = flow.getRttPacketPairs()
            rtt_data, srtt_data, time_data = _getPlotData(flow, packetPairs)
            med_index = int(len(rtt_data) / 2 - 1)
            if len(srtt_data) == 0:
                continue
            if len(srtt_data) == 1:
                med_index = 0
            med_srtt.append(srtt_data[med_index])
            med_time_data.append(flow.firstArrival)
        # plot
        initSubplot('Top Host Pairs In Terms of TCP Connections (' + str(count) + ' connections)', 'time (ms)', 'RTT (ms)')
        ax.plot(med_time_data, med_srtt, label='RTT')
        savePlot(filename+str(i))
