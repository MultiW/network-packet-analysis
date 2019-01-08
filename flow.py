from scapy.all import *

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

def _compute_packet_size(packet):
    try:
        return len(packet) - len(packet.payload.payload) + packet.len
    except AttributeError:
        return len(packet)

class Flow:
    def __init__(self, packet):
        ip = ""
        try:
            ip = packet[IP]
        except IndexError:
            ip = packet[IPv6]
        except:
            raise ValueError("Packet must contain an IP/IPv6 header")

        transport = ""
        typ = ""

        try:
            transport = packet[TCP]
            typ = "TCP"
        except IndexError:
            transport = packet[UDP]
            typ = "UDP"
        except:
            raise ValueError("Packet must contain a TCP/UDP header.")
        
        self.nodes = [(ip.src, transport.sport), (ip.dst, transport.dport)]

        # ---- Senders are either 0 or 1 (self.nodes[0] or self.nodes[1])
        # The last sender is the src of packet; this variable alternates depending on direction
        self.lastSender = 0
        # finishState: 0 - no FIN sent; 1 - FIN sent; 2 - FIN complete
        self.finishState = 0
        # finishReq is the sender who sent a FIN message first; -1 is set for undefined
        self.finishReq = -1
        self.resetState = 0

        self.type = typ
        self.firstArrival = packet.time
        self.lastArrival = packet.time
        
        # Each element in this list is (packet, interArrivalTime)
        self.packets = [(packet, 0)]
        self.ackPacketMap = {}
        self.updateState()
        
        self.totalSize = _compute_packet_size(packet)
        self.totalHeaderSize = len(packet) - len(packet[self.type].payload)
        self.maxInterArrivalTime = 0

    def getRttPacketPairs(self):
        packetPair = {} # int -> int: maps packet index to packet index
        unpairedPackets = {} # int -> int: ack -> packet
        for i in range(len(self.packets)):
            # packet isn't paired yet
            packetPair[i] = -1
            pkt = self.packets[i][0]
            unpairedPackets[pkt.ack] = i
            # find packet it's acknowledging
            seekingAck = pkt.seq
            if seekingAck in unpairedPackets: # It's a match
                pairPktInd = unpairedPackets[seekingAck]
                pairPkt = self.packets[pairPktInd][0]
                # if packet same direction
                if pairPkt.src == pkt.src:
                    continue
                packetPair[pairPktInd]  = i
                del unpairedPackets[seekingAck]
        return packetPair

    def addPacket(self, packet):
        p = (packet, packet.time - self.lastArrival)
        self.maxInterArrivalTime = max(self.maxInterArrivalTime, p[1])
        self.lastArrival = packet.time

        self.packets.append(p)
        self.totalSize += _compute_packet_size(packet)
        self.totalHeaderSize += len(packet) - len(packet[self.type].payload)

        # Check direction of flow
        ip = ""
        try:
            ip = packet[IP]
        except IndexError:
            ip = packet[IPv6]
        except:
            raise ValueError("Packet must contain an IP/IPv6 header")

        transport = ""
        try:
            transport = packet[TCP]
        except IndexError:
            transport = packet[UDP]
        except:
            raise ValueError("Packet must contain a TCP/UDP header.")

        if ((ip.src, transport.sport) == self.nodes[0]):
            self.lastSender = 0
        else:
            self.lastSender = 1

        self.updateState()

    def getDuration(self):
        return (self.lastArrival - self.firstArrival) * 1000

    def getTotalPackets(self):
        return len(self.packets)

    def getTotalSize(self):
        return self.totalSize

    def getOverheadRatio(self):
        if (self.totalHeaderSize != self.totalSize):
            return float(self.totalHeaderSize) / self.totalSize
        else:
            return 9999

    def getInterArrivalTimes(self):
        return [(p[1] * 1000) for p in self.packets]

    def getState(self):
        if (self.type == "TCP"):
            flag = self.packets[-1][0][TCP].flags
            threshold = (self.lastArrival - self.firstArrival) <= 5 * 60
            if (flag & SYN):
                if (threshold):
                    return "Request"
                else:
                    return "Failed"
            if (self.resetState):
                return "Reset"
            if (self.finishState == 2):
                return "Finished"
            if (threshold):
                return "Ongoing"

            return "Failed"
        else:
            return 0

    def updateState(self):
        if (self.type == "TCP"):
            flag = self.packets[-1][0][TCP].flags
            if (flag & FIN):
                if (self.finishState == 0):
                    self.finishState = 1
                    self.finishReq = self.lastSender
                elif (flag & ACK and self.lastSender != self.finishReq):
                    self.finishState = 2
            if (flag & RST):
                self.resetState = 1

    def isValid(self):
        return self.maxInterArrivalTime <= 90 * 60

class FlowList:
    def __init__(self):
        self.flows = {"TCP": {}, "UDP": {}}
        self.count = {"TCP": 0, "UDP": 0}
        self.uniqueFlows = {"TCP": [], "UDP": []}

    def populate(self, packetList):
        for packet in packetList:
                if (packet.haslayer(TCP) or packet.haslayer(UDP)):
                    if not(self.addPacket(packet)):
                        self.updateFlow(packet)

    # Return True if flow added; False if not added -- flow already exists
    def addFlow(self, flow):
        curFlows = self.flows[flow.type]
        for i in range(2):
            node = flow.nodes[i]
            
            # If we do not have a flow with this (IP, port), we can add it.
            if not (node in curFlows):
                break
            elif (i == 1):
                return False

            # Move into the dictionary by one more depth.
            curFlows = curFlows[node]
            
        curFlows = self.flows[flow.type]
        self.count[flow.type] += 1
        self.uniqueFlows[flow.type].append(flow)

        if not (flow.nodes[0] in curFlows):
            curFlows[flow.nodes[0]] = {flow.nodes[1] : flow}
        else:
            curFlows[flow.nodes[0]][flow.nodes[1]] = flow
        
        if not (flow.nodes[1] in curFlows):
            curFlows[flow.nodes[1]] = {flow.nodes[0] : flow}
        else:
            curFlows[flow.nodes[1]][flow.nodes[0]] = flow

        return True
    
    # Parse the packet into a Flow before adding
    # Return True if flow added; False if not added -- flow already exists or packet invalid
    def addPacket(self, p):
        try:
            flow = Flow(p)
        except ValueError:
            return False

        return self.addFlow(flow)

    # Update the flow info
    # Return True if flow updated; False if not updated -- flow doesn't exist or packet invalid
    def updateFlow(self, p):
        ip = ""
        try:
            ip = p[IP]
        except IndexError:
            ip = p[IPv6]
        except:
            return False

        transport = ""
        typ = ""

        try:
            transport = p[TCP]
            typ = "TCP"
        except IndexError:
            transport = p[UDP]
            typ = "UDP"
        except:
            return False

        curFlows = self.flows[typ]
        src = (ip.src, transport.sport)
        dst = (ip.dst, transport.dport)

        try:
            flow = curFlows[src][dst]
            flow.addPacket(p)
            return True
        except:
            return False

    def getTotalBytes(self, typ):
        total = 0
        for flow in self.uniqueFlows[typ]:
            total += flow.getTotalSize()

        return total

    def print(self):
        i = 0
        j = 0
        for key, val in self.flows["TCP"].items():
            for key2, val2 in val.items():
                print(key, " : ", key2)
                i += 1
        for key, val in self.flows["UDP"].items():
            for key2, val2 in val.items():
                print(key, " : ", key2)
                j += 1

        print("\n== TCP: " + str(i) + " ==")
        print("== UDP: " + str(j) + " ==")
        print("== Total: " + str(i + j) + " ==")