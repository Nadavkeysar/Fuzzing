import re
from scapy.all import *

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


def is_utf8(string):
    try:
        string.decode('utf-8')
    except UnicodeError:
        return False
    return True


# tests the ssh version packet to check if it's according to the protocol. if it's not - returns True
def test_if_invalid_ssh_protocol_version(payload):
    print("Incoming packet detected. Testing SSH protocol version header")

    print("- Testing header length")
    if len(payload) > 255: #payload should be under 255 bytes including the Carriage Return and Line Feed
        return True

    print("- Testing header additional lines not starting with 'SSH'")
    lines = payload.split(b'\x0d\x0a') # the version string payload can have other lines of data before the actual version stating with 'SSH', each ends with CR LF
    version_string_line = ""
    for line in lines:
        if line[:3] != b'SSH':
            if not is_utf8(line): # if a line doens't start with SSH and is non utf-8 (so not according to the protocol) we return
                return True
        else:
            version_string_line = line

    print("- Testing version string line starting with 'SSH' is ASCII encoded")
    if not version_string_line.isascii(): # the version string has to be ASCII
        return True

    print("- Testing version string is according to the SSH protocol's pattern")
    # version string can have options separated by space char. The pattern is: SSH-protoversion-softwareversion SP comments CR LF
    # we extract only the version string up until the space char
    version_string_raw = version_string_line.split()[0].decode()
    # checking the version string pattern is according to the protocol with regex
    version_string = re.match(r"SSH-[0-9].[0-9]-\S*", version_string_raw)
    if not version_string:
        return True
    print("+ SSH protocol version header OK")
    print("Version string is: %s" % version_string.string)
    return False


# based on the SSH RFC https://tools.ietf.org/html/rfc4253#section-4.2, in section 4.2 describing the Protocol Version Exchange
# we can see if the initial version exchange packets is according to the protocol or it's a fuzzing attempt
def check_fuzzing(packet):
    tcp_packet = packet[TCP]
    if tcp_packet.flags == SYN or tcp_packet.flags == ACK:
        # skipping the TCP handshake
        return
    if test_if_invalid_ssh_protocol_version(bytes(tcp_packet.payload)):
        print("Fuzzing detected")
    exit()




if __name__ == '__main__':
    #test_wrong = b'\xab\xd6\x00\x16\xe7\xec)\x1d\xf9\x0d\x0a\xd6\x99+P\x18\x01\xf6\xac;\x00\x00SSH-2.0-OpenSSH_8.3p1 Debian-1\x0d\x0a'
    #test_correct = b'blalbal\x0d\x0aSSH-2.0-OpenSSH_8.3p1 Debian-1\x0d\x0a'
    #ret = test_if_invalid_ssh_protocol_version(test_wrong)

    print("starting to sniff traffic, and filtering only incoming connection to destination port 22 (SSH)")
    sniff(filter="dst port 22", prn=check_fuzzing)