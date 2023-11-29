import pcapy
import socket
import struct
import textwrap
import time

TAB1 = '\t - '
TAB2 = '\t\t - '
TAB3 = '\t\t\t - '

DATA_TAB1 = '\t '
DATA_TAB2 = '\t\t '
DATA_TAB3 = '\t\t\t '

# Ethernet frame:
# //// sync 8 byte //// Receiver 6 byte //// Sender 6 byte ////Type 2 byte //// Payload 46-1500 byte //// crc 4 byte

def getEthernetFrame(data):
    # unpack packed data using struct
    destinationMac, sourceMac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return formatMacAddress(destinationMac), formatMacAddress(sourceMac), socket.htons(protocol), data[14:]


def formatMacAddress(bytes):
    # this takes the data and formats the mac address from destination and source

    byteString = map('{:02x}'.format, bytes)
    macAddress = ':'.join(byteString).upper()
    return macAddress


def ipv4Data(data):
    # after we get the ethernet frame we unpack it

    versionlength = data[0]
    # bit shift right to get version
    version = versionlength >> 4

    # to determine when needed data starts
    headerLength = (versionlength & 15) * 4

    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, headerLength, ttl, protocol, formatIpv4(src), formatIpv4(target), data[headerLength:]


def formatIpv4(address):
    # properly formats ipv4

    return '.'.join(map(str, address))


def icmpPacket(data):
    icmpType, code, checksum = struct.unpack('! B B H', data[:4])
    return icmpType, code, checksum, data[4:]


def tcpSegment(data):
    (sourcePort, destinationPort, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',
                                                                                                    data[:14])
    # bit shift again
    offset = (offset_reserved_flags >> 12) * 4
    flagUrg = (offset_reserved_flags & 32) >> 5
    flagAck = (offset_reserved_flags & 16) >> 4
    flagPsh = (offset_reserved_flags & 8) >> 3
    flagRst = (offset_reserved_flags & 4) >> 2
    flagSyn = (offset_reserved_flags & 2) >> 1
    flagFin = (offset_reserved_flags & 1)

    return sourcePort, destinationPort, sequence, acknowledgement, flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin, data[
                                                                                                                         offset:]

def udpSegment(data):
    sourcePort, destinationPort, size = struct.unpack('! H H 2x H', data[:8])
    return sourcePort, destinationPort, size, data[8:]


def formatMultiLine(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    # compatible with other machines ntohs

    makeConnection = pcapy.open_live(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)), 65536, True, 0)
    pcapWriter = makeConnection.dump_open("output.pcap")

    while True:
        start = time.time()
        rawData, _ = makeConnection.next()

        destinationMac, sourceMac, ethProtocol, data = getEthernetFrame(rawData)
        pcapWriter.dump(rawData)
        print()
        print("\nEthernet Frame: ")
        print(TAB1 + "Destination: {}, Source: {}, Protocol: {}".format(destinationMac, sourceMac, ethProtocol))

        if ethProtocol == 8:
            (version, header_length, ttl, protocol, src, target, data) = ipv4Data(data)
            print(TAB1 + "IPv4 Packet:", )
            print(TAB2 + "Version: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
            print(TAB2 + "Protocol: {}, Source: {}, Target: {} ".format(protocol, src, target))

            #go now to check type of packet
            if protocol == 1:
                # icmp
                icmpType, code, checksum, data = icmpPacket(data)
                print(TAB1 + "ICMP Packet:")
                print(TAB2 + "Type: {}, Code: {}, Checksum: {} ".format(icmpType, code, checksum))
                print(TAB2 + "Data:")
                print(formatMultiLine(DATA_TAB3, data))
                #data = str(data)

                #formattedSTR= textwrap.fill(data,width=75)
                #print(formattedSTR)


            elif protocol == 6:
                # tcp
                sourcePort, destinationPort, sequence, acknowledgement, flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin, data = tcpSegment(
                    data)
                print(TAB1 + "TCP Segment:")
                print(TAB2 + "Source Port: {}, Destination Port: {}, ".format(sourcePort, destinationPort))
                print(TAB2 + "Sequence: {}, Acknowledgment: {}".format(sequence,acknowledgement))
                print(TAB2 + "Flags:")
                print(TAB2 + "-URG: {}, -ACK: {}, -PSH: {}".format(flagUrg,flagAck,flagPsh))
                print(TAB3 + "-RST: {}, -SYN: {}, -FIN: {}".format(flagRst, flagSyn, flagFin))
                print(TAB2 + "Data:")
                print(formatMultiLine(DATA_TAB3, data))
                #data = str(data)

                #formattedSTR = textwrap.fill(data, width=75)
                #print(formattedSTR)


            elif protocol == 17:
                # udp
                sourcePort, destinationPort, length, data = udpSegment(data)
                print(TAB1 + "UDP Segment:")
                print(TAB2 + "Source Port: {}, Destination Port: {}, Length: {}".format(sourcePort, destinationPort, length))
            else:
                print(TAB1 + 'Data:')
                print(formatMultiLine(DATA_TAB2, data))
                continue
        else:
            print('Data:')
            print(formatMultiLine(DATA_TAB1, data))
    end = time.time()
    print("Total Duration:", end-start)

if __name__ == '__main__':
    main()
