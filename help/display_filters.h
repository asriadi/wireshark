/* THIS FILE IS AUTOMATICALLY GENERATED, DO NOT MODIFY!!! */
const char *display_filters_part[] = {
"Filtering packets while viewing \n"
"------------------------------- \n"
"After capturing packets or loading some network traffic from a file, Ethereal will display the packet data immediately on the screen. \n"
" \n"
"Using display filters, you can choose which packets should (not) be shown on the screen. This is useful to reduce the \"noice\" usually on the network, showing only the packets you want to. So you can concentrate on the things you are really interested in.  \n"
" \n"
"The display filter will not affect the data captured, it will only select for you which packets of the captured data are displayed on the screen. \n"
" \n"
"Everytime you change the filter string, all packets will be reread from the capture file (or from memory), and processed by the display filter \"machine\". Packet by packet, this \"machine\" is asked, if this particular packet should be shown or not. \n"
" \n"
"Ethereal offers a very powerful display filter language for this. It can be used for a wide range of purposes, from simply: \"show only packets from a specific IP address\", or on the other hand, to very complex filters like: \"find all packets where a special application specific flag is set\". \n"
" \n"
"Note: This display filter language is different from the one used for the Ethereal capture filters! \n"
" \n"
"------------------------------------------------- \n"
" \n"
"Some common examples: \n"
"--------------------- \n"
"Example Ethernet: display all traffic to and from the Ethernet address 08.00.08.15.ca.fe \n"
" \n"
"eth.addr==08.00.08.15.ca.fe \n"
" \n"
"Example IP: display all traffic to and from the IP address 192.168.0.10 \n"
" \n"
"ip.addr==192.168.0.10 \n"
" \n"
"Example TCP: display all traffic to and from the TCP port 80 (http) of all machines \n"
" \n"
"tcp.port==80 \n"
" \n"
"Examples combined: display all traffic to and from 192.168.0.10 except http \n"
" \n"
"ip.addr==192.168.0.10 && tcp.port!=80 \n"
" \n"
"Beware: The filter string builds a logical expression, which must be true to show the packet. The && is a \"logical and\", \"A && B\" means: A must be true AND B must be true to show the packet (it doesn't mean: A will be shown AND B will be shown).  \n"
" \n"
"------------------------------------------------- \n"
" \n"
"Hints: \n"
"Filtering can lead to side effects, which are sometimes not obvious at first sight. Example: If you capture TCP/IP traffic with the primitive \"ip\", you will not see the ARP traffic belonging to it, as this is a lower protocol layer than IP! \n"
};
#define DISPLAY_FILTERS_PARTS 1
#define DISPLAY_FILTERS_SIZE 2358
