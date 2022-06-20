## smurf ##

Super simple packet sniffer. Does not offer more than `tcpdump` or any other tool in the genre, as was written just for fun. 


The only current feature is that, unlike `tcpdump`, it can log which MAC address has visited which servers, and how many packets where transferred. That can be useful in combination with **ARP** spoofing.

``` sh
$ ./smurf -h
Usage: ./smurf [options]
        -i, --interface  <iface>           Specify which interface to use.
        -m, --monitor                      Try to set monitor mode (for wireless devices).
        -p, --promiscuous                  Try to set promiscuous mode.
        -w, --write <file>                 Dump packets to a file.
        -r, --file <file>                  Read packets in offline from file.
        -t, --tee <file>                   Like `-w', but also show packets on the screen.
        -l, --list-devices                 List available devices for capture.
        -c, --count <n>                    Analyze only n packets and exit.
        -v, --verbose                      Set verbose mode.
        -X, --hexdump                      Show hexdump.
        -Q, --direction <in|out|inout>     Set capture direction.
        -W, --watch-visits <file>          Watch peer internet activity and log in file.
        -h, --help                         Show this help message.
```

