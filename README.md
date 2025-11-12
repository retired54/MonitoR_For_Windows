# MonitoR_For_Windows
# one docc have code that watches the net in windows
           
  ***FIRST_OF_ALL***
  
  FIRST OF ALL : don't copy  and past , understand this notice :
 
 net_mw.cpp :  Single file Network Watcher for Windows (uses Npcap/wpcap)
 Features:
 1 list interfaces and let user choose
 2 capture live packets
 3 detect new MACs (first-seen)
 4 detect ARP IP->MAC changes (possible ARP spoofing)
 5 count DNS queries per source IP and alert on spike
 6 count outbound TCP SYNs per source IP and alert on burst
 7 log events to file
** Build (Developer Command Prompt):**

 cl /EHsc network_watch_win.cpp /I"C:\Path\To\Npcap\Include" /link /LIBPATH:"C:\Path\To\Npcap\Lib" wpcap.lib ws2_32.lib
 
Run :
net_mw.cpp
Notes:
//  - Requires Npcap installed. Must run elevated to open adapters.
//  - To capture raw 802.11 frames on Windows you also need adapter driver support and Npcap monitor mode enabled; this example treats Ethernet-layer packets (works for wired or Wi-Fi when adapter driver exposes link-layer Ethernet frames).
//  - Keep this code for defensive/legitimate monitoring on networks you control or have permission to monitor.
//  - i did what i coulD the rest According to ur knowledge
