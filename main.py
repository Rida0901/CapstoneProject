import socket
import struct
import textwrap


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


def formatIpv4(address):
    # properly formats ipv4

    return '.'.join(map(str, address))


def ipv4Data(data):
    # after we get the ethernet frame we unpack it

    versionlength = data[0]
    # bit shift right to get version
    version = versionlength >> 4

    # to determine when needed data starts
    headerLength = (versionlength & 15) * 4

    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, headerLength, ttl, protocol, formatIpv4(src), formatIpv4(target), data[headerLength:]


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


def main():
    # compatible with other machines ntohs

    makeConnection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        rawData, address = makeConnection.recvfrom(65536)

        destinationMac, sourceMac, ethProtocol, data = getEthernetFrame(rawData)
        print()
        print("Ethernet Frame: ")
        print("Destination: {}, Source: {}, Protocol: {}".format(destinationMac, sourceMac, ethProtocol))

        if ethProtocol == 8:
            (version, header_length, ttl, protocol, src, target, data) = ipv4Data(data)
            print("\tIPv4 Packet:", )
            print("\t\tVersion: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
            print("\t\tProtocol: {}, Source: {}, Target: {} ".format(protocol, src, target))

            #go now to check type of packet
            if protocol == 1:
                # icmp
                icmpType, code, checksum, data = icmpPacket(data)
                print("\tICMP Packet:")
                print("\t\tType: {}, Code: {}, Checksum: {} ".format(icmpType, code, checksum))
                print("\t\tData:")

                data = str(data)

                formattedSTR= textwrap.fill(data,width=75)
                print(formattedSTR)


            elif protocol == 6:
                # tcp
                sourcePort, destinationPort, sequence, acknowledgement, flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin, data = tcpSegment(
                    data)
                print("\tTCP Segment:")
                print("\t\tSource Port: {}, Destination Port: {}, ".format(sourcePort, destinationPort))
                print("\t\tSequence: {}, Acknowledgment: {}".format(sequence,acknowledgement))
                print("\t\tFlags:")
                print("\t\t\t-URG: {}, -ACK: {}, -PSH: {}".format(flagUrg,flagAck,flagPsh))
                print("\t\t\t-RST: {}, -SYN: {}, -FIN: {}".format(flagRst, flagSyn, flagFin))
                print("\t\tData:")

                data = str(data)

                formattedSTR = textwrap.fill(data, width=75)
                print(formattedSTR)


            elif protocol == 17:
                # udp
                sourcePort, destinationPort, length, data = udpSegment(data)
                print("\tUDP Segment:")
                print("\t\tSource Port: {}, Destination Port: {}, Length: {}".format(sourcePort, destinationPort, length))
            else:
                continue




if __name__ == '__main__':
    main()
