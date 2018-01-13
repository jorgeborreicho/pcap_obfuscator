# pcap_obfuscator

This is an old little program I wrote a while ago that takes a Wireshark PCAP file and anonymizes it. I called it the “PCAP obfuscator”. It uses a PyQT5 based GUI.

Sometimes we need to share PCAP files with people without disclosing the IP addresses used within our private networks. This program can randomly change IP addresses, MAC addresses and VLAN IDs while keeping the coherence of the packet sequence. It may also modify IP addresses in the payloads of text-based protocols like HTTP or SIP.

I must advise that it does not obfuscate addresses in ARP, DNS, DHCP and other protocols. My initial intent was to share Radius, Diameter, HTTP and SIP traces so I would always purge all of these ARP and DNS packets from the PCAP file using Wireshark before using this obfuscation tool. 

It is very simple to work with. You just need to open a PCAP file through the File menu, leave the “Type” field set to AUTO and press RUN. You will get an obfuscated.pcap file as the output. However, you can also edit the input and output filenames. 

If you leave it in AUTO and set the “Check Payload” checkbox, it will also go through the payload.

You can also set the “Type” to IP or MAC if you want to filter on a specific address and modify it as you wish. This also works for VLAN IDs.

Examples:

1 - Type = IP & Filter = 192.168.*.* & Modify = 172.16.*.*   

This will match all IP addresses from subnet 192.168.0.0/16 and modify the two most significant octets to 172.16.

2 - Type = MAC & Filter = aa:bb:cc:*:*:* & Modify = 11:22:*:*:dd:ee

This will match all MAC addresses from starting with aa:bb:cc and modify the two most significant octets to 11:22 and the two least significant octets to dd:ee.

3 - Type = VLAN & Filter = 30 & Modify = 1030   

This will match all packets with VLAN ID equal to 30 and modify them to VLAN 1030.

The Help menu has some hints on how to use these options. You can also check the Log from the View menu.

The PCAP Obfuscator only deals with IPv4 addresses for now. I might enhance it with IPv6 in the future and work on some protocol specific fields.

Cheers!
