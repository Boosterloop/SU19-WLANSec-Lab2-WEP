#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import binascii
import rc4

# wep key AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

# We read the original encrypted message from the wireshark file - rdpcap always returns an array, even if the pcap only contains one frame
# We will use the arp frame as a template for our own frame
templateFrame = rdpcap('arp.cap')[0]

# Same data as the arp frame
data = "\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8"

# ICV calculated with CRC 32
icv = binascii.crc32(data)
icv = struct.pack('<l', icv)

# Same IV as the arp frame
iv = templateFrame.iv

# Data and ICV to crypt
toCrypt = data + icv
# Seed formed by IV and key
seed = iv + key

# Crypt the data and ICV using RC4
crypted = rc4.rc4crypt(toCrypt, seed)

# We get back the encrypted ICV and unpack it to have a Long int
(intIcv,) = struct.unpack('!L', crypted[-4:])

# We change the fields' value in the template frame to replace them with our own
templateFrame.wepdata = crypted[:-4]
templateFrame.icv = intIcv

# Write a new pcap file
wrpcap("crypted.cap", templateFrame)