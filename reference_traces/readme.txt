This directory contains some sim traces that can be used as references when
adding or debugging the dissector. The files are named using the following
convention
simtrace2_<what was captured>.pcapng
spy_export_html_<what was captured>.html

Example:
simtrace2_bg95_boot_roam_profile.pcapng
spy_export_html_bg95_boot_roam_profile.html

The PCAP file was captured in Wireshark as the simtrace2 board was directing
captured traffic to Wireshark.

The html file was captured using the UL Mobile Spy tool as a reference and the
output exported to html format.

These files where captured at the same time for the exact same traffic and should
line up exactly or within one or two packets at the beginning. The simtrace2 board
does not export the ATR commands so those might appear in the html but not in the
pcap file.
