from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2

# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = string[count + 1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def build_packet():
    myChecksum = 0
    packetID = os.getpid() & 0xFFFF

    # Header: type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, packetID, 1)
    data = struct.pack("d", time.time())

    myChecksum = checksum(header + data)

    # Insert the checksum into the packet
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, htons(myChecksum), packetID, 1)
    packet = header + data
    return packet


def get_route(hostname):
    timeLeft = TIMEOUT
    print("Traceroute to", hostname, "(" + gethostbyname(hostname) + ")")

    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)

            # Make a raw socket named mySocket
            mySocket = socket(AF_INET, SOCK_RAW, getprotobyname("icmp"))

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)

            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)

                if whatReady[0] == []:
                    print(" * * * Request timed out.")
                    continue

                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()

                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print(" * * * Request timed out.")
                    continue

            except timeout:
                continue

            else:
                # Fetch the icmp type from the IP packet
                icmpHeader = recvPacket[20:28]
                icmpType, code, check, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
                types = icmpType

                if types == 11:
                    bytes_in_double = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes_in_double])[0]
                    print(" %d rtt=%.0f ms %s" % (ttl, (timeReceived - t) * 1000, addr[0]))

                elif types == 3:
                    bytes_in_double = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes_in_double])[0]
                    print(" %d rtt=%.0f ms %s" % (ttl, (timeReceived - t) * 1000, addr[0]))

                elif types == 0:
                    bytes_in_double = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes_in_double])[0]
                    print(" %d rtt=%.0f ms %s" % (ttl, (timeReceived - timeSent) * 1000, addr[0]))
                    return

                else:
                    print("error")
                    break

            finally:
                mySocket.close()


get_route("openai.com")