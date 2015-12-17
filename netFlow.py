#!/usr/bin/env python

""" This NetFLow collector supports IPv4 only and NetFlow 1, 5 versions"""
# It is inspired by http://www.mindrot.org/misc/ and expanded to NetFlow 5, the aim is to expand it to the Netflow version 9:

import select
import socket
import struct
import numpy as np


"""  Virtual classes """


class Header(object):
    LENGTH = 0

    def __init__(self, data):
        if len(data) != self.LENGTH:
            raise ValueError("Short flow header")


class Flow(object):
    LENGTH = 0

    def __init__(self, data):
        if len(data) != self.LENGTH:
            pass
            raise ValueError("Short flow")

    def _int_to_ipv4(self, addr4):
        self.name = "{}.{}.{}.{}".format(addr4 >> 24 & 0xff, addr4 >> 16 & 0xff, addr4 >> 8 & 0xff, addr4 & 0xff)
        return self.name

"""  Sub-classes Flow v 1 """

class Header1(Header):
    LENGTH = struct.calcsize("!HHIII")

    def __init__(self, data):
        super().__init__(data)
        if len(data) != self.LENGTH:
            raise ValueError("Short flow header")

        ###
        # https://www.plixer.com/support/netflow_v1.html
        # Bytes	Contents	Description
        # 0-1	version	    NetFlow export format version number
        # 2-3	count	    Number of flows exported in this packet (1-24)
        # 4-7	sys_uptime	Current time in milliseconds since the export device booted
        # 8-11	unix_secs	Current count of seconds since 0000 UTC 1970
        # 12-16	unix_nsecs	Residual nanoseconds since 0000 UTC 1970
        ###

        _headpart = struct.unpack("!HHIII", data)
        self.version = _headpart[0]
        self.count = _headpart[1]
        self.sys_uptime = _headpart[2]
        self.unix_secs = _headpart[3]
        self.unix_nsecs = _headpart[4]

    def __str__(self):
        """ Print current information from a header """
        prt = "NetFlow Header v.%d containing %d flows\n" % \
              (self.version, self.count)
        prt += "    Router uptime: %s\n" % np.array(self.sys_uptime).astype("M8[ms]")
        prt += u"    Current time:{0:d}.{1:09d}\n".format(self.unix_secs, self.unix_nsecs)
        prt += "Time: %s\n" % np.array(self.unix_secs).astype("datetime64[s]")
        return prt


class Flow1(Flow):
    LENGTH = struct.calcsize("!IIIHHIIIIHHHBBBBBBI")

    def __init__(self, data):
        super().__init__(data)
        if len(data) != self.LENGTH:
            raise ValueError("Short flow")

        ###
        # https://www.plixer.com/support/netflow_v1.html
        # Bytes	Contents	Description
        # 0-3	srcaddr	Source IP address
        # 4-7	dstaddr	Destination IP address
        # 8-11	nexthop	IP address of next hop router
        # 12-13	input	SNMP index of input interface
        # 14-15	output	SNMP index of output interface
        # 16-19	dPkts	Packets in the flow
        # 20-23	dOctets	Total number of Layer 3 bytes in the packets of the flow
        # 24-27	first	SysUptime at start of flow
        # 28-31	last	SysUptime at the time the last packet of the flow was received
        # 32-33	srcport	TCP/UDP source port number or equivalent
        # 34-35	dstport	TCP/UDP destination port number or equivalent
        # 36-37	pad1	Unused (zero) bytes
        # 38	prot	IP protocol type (for example, TCP = 6; UDP = 17)
        # 39	tos	IP type of service (ToS)
        # 40	flags	Cumulative OR of TCP flags
        # 41-48	pad2	Unused (zero) bytes
        ###

        _flowpart = struct.unpack("!IIIHHIIIIHHHBBBBBBI", data)
        self.srcaddr = self._int_to_ipv4(_flowpart[0])
        self.dstaddr = self._int_to_ipv4(_flowpart[1])
        self.nexthop = self._int_to_ipv4(_flowpart[2])
        self.input = _flowpart[3]
        self.output = _flowpart[4]
        self.dPkts = _flowpart[5]
        self.dOctets = _flowpart[6]
        self.first = _flowpart[7]
        self.last = _flowpart[8]
        self.srcport = _flowpart[9]
        self.dstport = _flowpart[10]
        # pad1 unused (zero) bytes
        self.prot = _flowpart[12]
        self.tos_IP = _flowpart[13]
        self.flags = _flowpart[14]
        # pad2 unused (zero) bytes

    def __str__(self):

        self.protocol = {}
        PROTOCOL_TYPES = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            # Add protocols here

        }

        if self.prot in PROTOCOL_TYPES.keys():
            self.protocol = PROTOCOL_TYPES[self.prot]
        else:
            self.protocol = str(self.prot)

        ret = u'Protocol: {0:s} : {1:s}:{2:d} > {3:s}:{4:d} {5:d} bytes : ToS: {6:d}' \
            .format(self.protocol, self.srcaddr, self.srcport, self.dstaddr, self.dstport, self.dOctets, self.tos_IP)

        return ret


"""  Sub-classes Flow v 5 """


class Header5(Header):
    ###
    # https://www.plixer.com/support/netflow_v5.html
    # Bytes	Contents	        Description
    # 0-1	version	            NetFlow export format version number
    # 2-3	count	            Number of flows exported in this packet (1-30)
    # 4-7	sys_uptime	        Current time in milliseconds since the export device booted
    # 8-11	unix_secs	        Current count of seconds since 0000 UTC 1970
    # 12-15	unix_nsecs	        Residual nanoseconds since 0000 UTC 1970
    # 16-19	flow_sequence	    Sequence counter of total flows seen
    # 20	engine_type	        Type of flow-switching engine
    # 21	engine_id	        Slot number of the flow-switching engine
    # 22-23	sampling_interval	First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
    ###

    LENGTH = struct.calcsize("!HHIIIIBBH")

    def __init__(self, data):

        super().__init__(data)
        if len(data) != self.LENGTH:
            raise ValueError("Short flow header")

        _headpart = struct.unpack("!HHIIIIBBH", data)
        self.version = _headpart[0]
        self.count = _headpart[1]
        self.sys_uptime = _headpart[2]
        self.unix_secs = _headpart[3]
        self.unix_nsecs = _headpart[4]
        self.flow_sequence = _headpart[5]
        self.engine_type = _headpart[6]
        self.engine_id = _headpart[7]
        self.sampling_interval = _headpart[8]

    def __str__(self):
        """ Print current information from a header """
        prt = "NetFlow Header v.%d containing %d flows\n" % \
              (self.version, self.count)
        prt += "    Router uptime: %d\n" % self.sys_uptime
        prt += u"    Current time:  {0:d}.{1:09d}: \n".format(self.unix_secs, self.unix_nsecs)
        prt += u" Current time in 64 format: %s \n" % np.array(self.unix_secs).astype("datetime64[s]")

        return prt


class Flow5(Flow):
    ###
    # https://www.plixer.com/support/netflow_v5.html
    # Bytes	Contents	Description
    # 0-3	srcaddr	    Source IP address
    # 4-7	dstaddr	    Destination IP address
    # 8-11	nexthop	    IP address of next hop router
    # 12-13	input	    SNMP index of input interface
    # 14-15	output	    SNMP index of output interface
    # 16-19	dPkts	    Packets in the flow
    # 20-23	dOctets	    Total number of Layer 3 bytes in the packets of the flow
    # 24-27	first	    SysUptime at start of flow
    # 28-31	last	    SysUptime at the time the last packet of the flow was received
    # 32-33	srcport	    TCP/UDP source port number or equivalent
    # 34-35	dstport	    TCP/UDP destination port number or equivalent
    # 36	pad1	    Unused (zero) bytes
    # 37	tcp_flags	Cumulative OR of TCP flags
    # 38	prot	    IP protocol type (for example, TCP = 6; UDP = 17)
    # 39	tos	IP      type of service (ToS)
    # 40-41	src_as	    Autonomous system number of the source, either origin or peer
    # 42-43	dst_as	    Autonomous system number of the destination, either origin or peer
    # 44	src_mask	Source address prefix mask bits
    # 45	dst_mask	Destination address prefix mask bits
    # 46-47	pad2	    Unused (zero) bytes
    ###

    LENGTH = struct.calcsize("!IIIHHIIIIHHBBBBHHBBH")

    def __init__(self, data):
        super().__init__(data)
        if len(data) != self.LENGTH:
            raise ValueError("Short flow")

        _flowpart = struct.unpack("!IIIHHIIIIHHBBBBHHBBH", data)
        self.srcaddr = self._int_to_ipv4(_flowpart[0])
        self.dstaddr = self._int_to_ipv4(_flowpart[1])
        self.nexthop = self._int_to_ipv4(_flowpart[2])
        self.input = _flowpart[3]
        self.output = _flowpart[4]
        self.dPkts = _flowpart[5]
        self.dOctets = _flowpart[6]
        self.first = _flowpart[7]
        self.last = _flowpart[8]
        self.srcport = _flowpart[9]
        self.dstport = _flowpart[10]
        self.pad1 = _flowpart[11]
        self.tcp_flag = _flowpart[12]
        self.prot = _flowpart[13]
        self.tos_IP = _flowpart[14]
        self.src_as = _flowpart[15]
        self.dst_as = _flowpart[16]
        self.src_mask = _flowpart[17]
        self.dst_mask = _flowpart[18]
        # pad2 unused (zero) bytes

    def __str__(self):

        self.protocol = {}
        PROTOCOL_TYPES = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            # Add protocols here

        }

        if self.prot in PROTOCOL_TYPES.keys():
            self.protocol = PROTOCOL_TYPES[self.prot]
        else:
            self.protocol = str(self.prot)

        ret = u' Protocol: {0:s} : {1:s}:{2:d} > {3:s}:{4:d} {5:d} bytes : ToS: {6:d} Next Hop: {7:s}: {8:d}: {9:d}' \
            .format(self.protocol, self.srcaddr, self.srcport, self.dstaddr, self.dstport, self.dOctets, self.tos_IP,
                    self.nexthop, self.first, self.last)
        return ret



class NetFlowPacket:
    FLOW_TYPES = {
        1: (Header1, Flow1),
        5: (Header5, Flow5),

    }

    def __init__(self, data):
        """ Observe flow version"""
        if len(data) < 16:
            raise ValueError("Short packet")
        _headerpart = struct.unpack("!H", data[:2])
        self.version = _headerpart[0]

        if not self.version in self.FLOW_TYPES.keys():
            print("NetFlow version %d is not yet implemented" % self.version)

        hdr_class = self.FLOW_TYPES[self.version][0]
        flow_class = self.FLOW_TYPES[self.version][1]

        # Extracted header
        self.header = hdr_class(data[:hdr_class.LENGTH])

        # Control packet
        if self.version == 9:
            print("Version Flow 9 detected, in demo ")

        else:
            if len(data) - self.header.LENGTH != (self.header.count * flow_class.LENGTH):
                raise ValueError("Packet truncated in flow data")

        self.flows = []

        for n in range(self.header.count):
            offset = self.header.LENGTH + (flow_class.LENGTH * n)
            flow_data = data[offset:offset + flow_class.LENGTH]
            self.flows.append(flow_class(flow_data))

    def __str__(self):
        ret = str(self.header)
        i = 0
        for flow in self.flows:
            ret += "Flow %d: " % i
            ret += "%s\n" % str(flow)
            i += 1

        return ret


class Rec(object):
    def __init__(self, port="4002", host=None):
        self.host = host
        # listening port
        self.port = port
        self.addrs = socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE)
        self.socks = []

        for addr in self.addrs:
            self.sock = socket.socket(addr[0], addr[1])
            self.sock.bind(addr[4])
            self.socks.append(self.sock)

            print("listening on [%s]:%d" % (addr[4][0], addr[4][1]))

    def rec_packet(self):
        while 1:
            (rlist, wlist, xlist) = select.select(self.socks, [], self.socks)


            for sock in rlist:
                (data, addrport) = sock.recvfrom(8192)
                print("Received flow packet from %s:%d" % addrport)
                print(NetFlowPacket(data))


if __name__ == '__main__':
    rec = Rec("4710")
    rec.rec_packet()
