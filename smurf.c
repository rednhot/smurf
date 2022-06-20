/* Simple network sniffer 
   
   author: mathway */

#include "util.h"
#include "network_defs.h"
#include "peer.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#define DEBUG(...)						\
    do {							\
	if (flag_verbose) log_message(stderr, __VA_ARGS__);	\
    } while (0)

#define FILTER_LEN 1000


/* Displays help message */
static void show_help(const char *exename); 

/* User menu for choosing capture device */
static const char* choose_device(void); 

/* Handles some abnormality */
static void handle_warning_or_error(int status, pcap_t *cap_handle); 

/* Extracts useful information from packet */
static void handle_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes);

/* Checks if device is ok for capture */
static int device_is_capturable(const char *device_name); 

/* Analyze data link layer data. Returns offset where upper layer starts */
static int analyze_link(const u_char *data, int *type);

/* Analyze network layer data. Returns offset where upper layer starts */
static int analyze_net(const u_char *data, int *type);

/* Analyze transport layer data. Returns offset where upper layer starts */
static int analyze_trans(const u_char *data, int *type, int before);

/* Parse user options */
static void parse_options(int argc, char* argv[]);

/* Flush run-time stats to file */
static void flush_watchfile(void);

/* Catch-all signal handler */
static void signal_handler(int signum);

/* Buffer for error descriptions specific to PCAP(3) */
static char errbuf[PCAP_ERRBUF_SIZE]; 
static char filter_expression[FILTER_LEN];
static const char *cap_device, *input_filename, *output_filename, *watchfile;
static int flag_tee, flag_promisc, flag_monitor, flag_list_dev, flag_verbose, flag_visits, flag_dump; /* Misc flags */
static int packet_num;
static pcap_dumper_t *dumper_file = NULL;
static pcap_direction_t direction = PCAP_D_INOUT;
static struct bpf_program cap_filter;
static bpf_u_int32 cap_dev_net, cap_dev_mask;
static struct in_addr cap_dev_addr;
static pcap_t *cap_handle = NULL;

/* Network peers array */
struct net_peer peers[MAX_PEERS];
int peer_count;


int
main(int argc, char **argv)
{
    int s;
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    /* Parse user options */
    parse_options(argc, argv);

    /* Setup signal handlers */
    
    /* Initializing pcap library */
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf))
	errx(EXIT_FAILURE, "Can't initialize pcap library: %s", errbuf);

    /* Determining the source of packets */
    if (input_filename)
    {
	/* User has specified the capture file on the commanad line */
	if ((cap_handle = pcap_open_offline(input_filename, errbuf)) == NULL)
	    errx(EXIT_FAILURE, "Can't read from file: %s", errbuf);
    } else
    {
	/* Give user an opportunity to choose device from a menu,
	   in case he hasn't done it yet on the command line */
	if (!cap_device)
	    cap_device = choose_device();
	log_message(stderr, "Selected device: %s", cap_device);
	if ((cap_handle = pcap_create(cap_device, errbuf)) == NULL)
	    errx(EXIT_FAILURE, "Can't create a handle: %s", errbuf);

	/* Promiscious mode setting */
	if (flag_promisc)
	{

	    DEBUG("Promiscuous mode is set");

	    s = pcap_set_promisc(cap_handle, 1);
	    if (s)
		handle_warning_or_error(s, cap_handle);
	}

	/* Monitor mode setting from wireless devices */
	if (flag_monitor)
	{

	    DEBUG("Trying to set monitor mode");

	    s = pcap_set_rfmon(cap_handle, 1);
	    if (s)
		handle_warning_or_error(s, cap_handle);
	}

	/* Will deliver packats to the application ASAP */
	pcap_set_immediate_mode(cap_handle, 1);


	/* All handle preparations are done. Now activete it! */
	s = pcap_activate(cap_handle);
	if (s)
	    handle_warning_or_error(s, cap_handle);

	cap_dev_addr = get_dev_addr(cap_device);
    }
    DEBUG("snapshot len is %d", pcap_snapshot(cap_handle));


    /* If user has specified output file, then let's use it */
    if (output_filename)
    {
	dumper_file = pcap_dump_open(cap_handle, output_filename);
	if (!dumper_file)
	    errx(EXIT_FAILURE, "Can't open pcap file for writing: %s", pcap_geterr(cap_handle));
	log_message(stderr, "dumper_file is %p", dumper_file);
    }

    if (dumper_file)
	DEBUG("output filename is %s", output_filename);

    switch(direction)
    {
    case PCAP_D_IN:
	DEBUG("direction is IN");
	break;
    case PCAP_D_OUT:
	DEBUG("direction is OUT");
	break;
    case PCAP_D_INOUT:
	DEBUG("direction is INOUT");
	break;
    default:
	DEBUG("Unknown direction");
    }

    /* Applying capture direction contraints */
    if (!input_filename && pcap_setdirection(cap_handle, direction))
	errx(EXIT_FAILURE, "Can't set direction: %s", pcap_geterr(cap_handle));


    /* Compile & apply capture filters */
    if (strlen(filter_expression))
    {
	DEBUG("trying to apply filter expression is \"%s\"", filter_expression);    
	if (!strcmp(cap_device, "any") || input_filename)
	{
	    if (pcap_compile(cap_handle,
			     &cap_filter,
			     filter_expression,
			     0,
			     PCAP_NETMASK_UNKNOWN) == PCAP_ERROR)
	    {
		errx(EXIT_FAILURE,
		     "Can't compile filter program: %s",
		     pcap_geterr(cap_handle));
	    }
	} else
	{
	    if (pcap_lookupnet(cap_device, &cap_dev_net, &cap_dev_mask, errbuf) == PCAP_ERROR)
		errx(EXIT_FAILURE,
		     "Can't lookup address information of device \"%s\"",
		     cap_device);

	    if (pcap_compile(cap_handle,
			     &cap_filter,
			     filter_expression,
			     0,
			     cap_dev_mask) == PCAP_ERROR)
	    {
		errx(EXIT_FAILURE,
		     "Can't compile filter program: %s",
		     pcap_geterr(cap_handle));
	    }
	}
	if (pcap_setfilter(cap_handle, &cap_filter) == PCAP_ERROR)
	    errx(EXIT_FAILURE,
		 "Can't set filter for capture: %s",
		 pcap_geterr(cap_handle));
	pcap_freecode(&cap_filter);
    }

    /* And here the real capture starts */
    log_message(stderr, "Capture started!");
    s = pcap_loop(cap_handle, packet_num, handle_packet, (u_char*)cap_handle);
    if (s == PCAP_ERROR)
	handle_warning_or_error(s, cap_handle);

    print_visit_stats(stdout);
}

static const char*
choose_device(void)
{
    pcap_if_t *dev,*tmp_dev;
    int i, user_opt, id_w = 2, name_w = 10, desc_w = 34, ip_w = 15,
	good_dev_count=0, dev_map[30], flag;
    char *device_name;

    if (pcap_findalldevs(&dev, errbuf))
	errx(EXIT_FAILURE, "Can't find devices: %s", errbuf);
    if (!dev)
	errx(EXIT_FAILURE, "No device accessible for capture");

    printf("+---------------------------------------------------------------------+\n");
    printf("|                     DEVICES                                         |\n");
    printf("+----+----------+------------------+----------------------------------+\n");
    printf("| Id |   Name   |       IP         |            Description           |\n");
    printf("+----+----------+------------------+----------------------------------+\n");

    for (tmp_dev=dev, i=0; tmp_dev; tmp_dev = tmp_dev->next, ++i)
    {
	/* Check if interface is ok for capturing.
           TODO: Add support for more address families that AF_INET */
	if (!(tmp_dev->flags & PCAP_IF_UP &&
	      tmp_dev->flags & PCAP_IF_RUNNING &&
	      tmp_dev->flags & PCAP_IF_CONNECTION_STATUS_CONNECTED))
	    continue;

	flag=0;
	if (tmp_dev->addresses)
	{
	    for (; tmp_dev->addresses ; tmp_dev->addresses = tmp_dev->addresses->next)
		if (tmp_dev->addresses->addr->sa_family == AF_INET)
		{
		    flag=1;
		    break;
		}
	    if (!flag)
		continue;
	} else /* if (strcmp(tmp_dev->name,"any")) */
	    continue;

	printf("| %*d |%*.*s| ",
	       id_w, good_dev_count+1,
	       name_w, name_w, tmp_dev->name);	       
	if (tmp_dev->addresses)
	    printf("%*.*s",
		   ip_w, ip_w, inet_ntoa(((struct sockaddr_in*)tmp_dev->addresses->addr)->sin_addr));
	else
	    printf("%*.*s",
		   ip_w, ip_w, "0.0.0.0");
	printf("  |");
	if (tmp_dev->description)
	    printf("%2$*1$.*1$s", desc_w, tmp_dev->description);
	else
	{
	    if (tmp_dev->flags & PCAP_IF_WIRELESS)
		printf("%2$*1$.*1$s", desc_w, "Wireless interface");
	    else if (strstr(tmp_dev->name, "eth"))
		printf("%2$*1$.*1$s", desc_w, "Ethernet interface");
	    else if (tmp_dev->flags & PCAP_IF_LOOPBACK)
		printf("%2$*1$.*1$s", desc_w, "Loopback interface");
	    else
		printf("%*s", desc_w, "Unknown interface");
	}
	printf("|");
	dev_map[good_dev_count++] = i;
	
	printf("\n+----+----------+------------------+----------------------------------+\n");
    }

    if (flag_list_dev == 1)
	exit(EXIT_SUCCESS);
    
    printf("Choose device number: ");
    while (1)
    {
	scanf("%d", &user_opt);
	if (user_opt >= 1 && user_opt <= good_dev_count)
	    break;
	newline_flush(stdin);
	printf("Wrong choice! Enter again: ");
    }

    tmp_dev = dev;
    for (i = 0; i < dev_map[user_opt-1]; ++i)
	tmp_dev = tmp_dev->next;
    device_name = strdup(tmp_dev->name);
    pcap_freealldevs(dev);

    return device_name;
}

static void
handle_warning_or_error(int status, pcap_t *cap_handle)
{
    	switch (status)
	{
	case PCAP_WARNING_PROMISC_NOTSUP:
	    warnx("Can't set promiscous mode on the device");
	    break;
	case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
	    warnx("Requested timestamp type is not supported for the device");
	    break;
	case PCAP_WARNING:
	    warnx("Warning: %s", pcap_geterr(cap_handle));
	    break;

	case PCAP_ERROR_ACTIVATED:
	    errx(EXIT_FAILURE, "The handle has already been activated");
	    break;
	case PCAP_ERROR_NO_SUCH_DEVICE:
	    errx(EXIT_FAILURE, "No such device");
	    break;
	case PCAP_ERROR_PERM_DENIED:
	    errx(EXIT_FAILURE, "Can't open capture soruce: Permission denied");
	    break;
	case PCAP_ERROR_PROMISC_PERM_DENIED:
	    errx(EXIT_FAILURE, "Can't put device in promiscoue mode: Permission denied");
	    break;
	case PCAP_ERROR_RFMON_NOTSUP:
	    errx(EXIT_FAILURE, "Monitor mode is not supported for the device");
	    break;
	case PCAP_ERROR_IFACE_NOT_UP:
	    errx(EXIT_FAILURE, "Device is down");
	    break;
	case PCAP_ERROR:
	    errx(EXIT_FAILURE, "Some error occured: %s", pcap_geterr(cap_handle));
	    break;
	default:
	    errx(EXIT_FAILURE, "Undefined error occured: %s", pcap_geterr(cap_handle));
	}
}

static void
handle_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes)
{
    static int packet_count = 0;
    int off, type = 0;
    printf("==== Got a %d byte packet ====\n", header->len);
    type = pcap_datalink((pcap_t*) user);
    if (!dumper_file || flag_tee)
    {
	if (flag_dump == 2)
	    hexdump((char*)bytes, header->caplen);

	off = analyze_link(bytes, &type);
	if (off == -1)
	    goto cont;
	bytes += off;
	off = analyze_net(bytes, &type);
	if (off == -1)
	    goto cont;
	bytes += off;

	off = analyze_trans(bytes, &type, off);
	if (off == -1)
	    goto cont;
	bytes += off;
    }
    else
	pcap_dump((u_char*) dumper_file, header, bytes);
cont:
    puts("");
}

static int
analyze_link(const u_char *data, int *type)
{
    int header_len = -1;
    if (*type == DLT_EN10MB)
    {
	/* Ethernet */
	printf("[[  Layer 2 :: Ethernet  ]]\n");
	header_len = ETHER_HDR_LEN;
	
	const struct ether_hdr *eh = (const struct ether_hdr*) data;
	char *src_addr = strdup(mac_to_ascii(eh->src_addr));
	char *dst_addr = strdup(mac_to_ascii(eh->dst_addr));

	*type = ntohs(eh->proto);

	printf("[ Source: %s\tDest: %s ]\n", src_addr, dst_addr);
	free(src_addr);
	free(dst_addr);
    } else
    {
	fprintf(stderr, "Got unsupported link-layer header");
    }
    return header_len;
}

static int
analyze_net(const u_char *data, int *type)
{
    int header_len = -1;

    if (*type == ETHER_P_IP)
    {
	/* It's IPv4 packet */
	struct ip_hdr *ih = (struct ip_hdr *) data;
	char *src_addr = strdup(inet_ntoa(ih->saddr)),
	    *dst_addr = strdup(inet_ntoa(ih->daddr));
	printf("\t((  Level 3 ::: Internet Protocol  ))\n");
	printf("\t( Source: %s\tDest: %s )\n", src_addr, dst_addr);
	printf("\t( Hlen: %d\tTotal length: %d )\n",
	       ih->h_len * 4,
	       ntohs(ih->total_len));
	printf("\t( ttl: %d\tProto: %#02hhx )\n",
	       ih->ttl, ih->proto);
	printf("\t( Id: %d\tCheck: %#04hx )\n",
	       ntohs(ih->ident),
	       ntohs(ih->h_check));
	*type = ih->proto;

	if (flag_visits && memcmp(&ih->daddr, &cap_dev_addr, 4))
	{
	    /* We are watching peer activity on the network */
	    struct ether_hdr *ma = (struct ether_hdr*) (data-ETHER_HDR_LEN);
	    int ind;
	    for (ind = 0; ind < peer_count; ++ind)
	    {
		if (!memcmp(&peers[ind].hw_addr, &ma->src_addr, ETHER_ADDR_LEN))
		    break;
	    }
	    if (ind == peer_count)
	    {
		if (peer_count == MAX_PEERS)
		    goto cont;
		peers[ind] = create_peer(ma->src_addr, "Unnamed");
		peer_count++;
	    }
	    make_visit(&peers[ind], ih->daddr);
	}
    cont:
	header_len = ih->h_len * 4;
	free(src_addr);
	free(dst_addr);
    } else if (*type == ETHER_P_ARP)
    {
	struct arp_hdr *ah = (struct arp_hdr*) data;
	char *src_hw_addr = strdup(mac_to_ascii(*(struct mac_addr*)&ah->src_hw_addr)),
	     *src_pr_addr = strdup(inet_ntoa(*(struct in_addr*)&ah->src_pr_addr)),
 	     *dst_hw_addr = strdup(mac_to_ascii(*(struct mac_addr*)&ah->dst_hw_addr)),
	     *dst_pr_addr = strdup(inet_ntoa(*(struct in_addr*)&ah->dst_pr_addr));
	u16 op_num = ntohs(ah->op);
	char *op =
	    (op_num == ARP_OP_REQUEST) ? "REQUEST" :
	    (op_num == ARP_OP_REPLY)  ? "REPLY" :
	    (op_num == ARP_OP_INREPLY) ? "INREPLY" :
	    (op_num == ARP_OP_INREQUEST) ? "INREQUEST":
	    (op_num == ARP_OP_NAK) ? "NAK" :
	    (op_num == ARP_OP_RREPLY) ? "RREPLY" :
	    (op_num == ARP_OP_RREQUEST) ? "RREQUEST" : "?";	    
	
	printf("\t((  Level 3 ::: Address Resolution Protocol  ))\n");
	printf("\t( Operation: %s )\n", op);
	printf("\t( SourceHA: %17s\tDestHA: %17s )\n"
	       "\t( SourcePA: %17s\tDestPA: %17s )\n",
	       src_hw_addr, dst_hw_addr, src_pr_addr, dst_pr_addr);
	free(src_hw_addr);
	free(src_pr_addr);
	free(dst_hw_addr);
	free(dst_pr_addr);
    }
    else if (*type == ETHER_P_LOOP)
    {
	puts("It's an Ethernet Loopback packet!");
	return -1;
    } else
    {
	puts("Unknown network layer protocol :(");
    }
	
    return header_len;
}

static int
analyze_trans(const u_char *data, int *type, int before)
{
    int header_len = -1;
    if (*type == IP_PROTO_TCP)
    {
	struct tcp_hdr *th = (struct tcp_hdr*)  data;
	printf("\t\t{{  Level 4 :::: Transmission Control Protocol  }}\n");
	printf("\t\t{ SrcPort: %5d\tDstPort: %5d }\n",
	       ntohs(th->sport), ntohs(th->dport));
	printf("\t\t{ Seq: %10u\tAck: %u }\n",
	       ntohl(th->seq_num), ntohl(th->ack_num));
	header_len = th->dat_off * 4;
	printf("\t\t{ HLen: %d\tFlags: |", header_len);
	if (th->ns)
	    printf("NS|");
	if (th->cwr)
	    printf("CWR|");
	if (th->ece)
	    printf("ECE|");
	if (th->urg)
	    printf("URG|");
	if (th->ack)
	    printf("ACK|");
	if (th->psh)
	    printf("PSH|");
	if (th->rst)
	    printf("RST|");
	if (th->syn)
	    printf("SYN|");
	if (th->fin)
	    printf("FIN");
	printf(" }\n");
	printf("\t\t{ WinSz: %d\tChecksum: %4x }\n",
	       ntohs(th->win_sz), ntohs(th->chk));
	if (flag_dump == 1)
	{
	    int payload_len;
	    struct ip_hdr *ih = ((struct ip_hdr*)(data-before));
	    payload_len = ntohs(ih->total_len)-(ih->h_len+th->dat_off)*4;
	    if (payload_len)
	    {
		printf("-=-= Payload %d bytes =-=-\n", payload_len);
		hexdump((const char*)data+(th->dat_off*4), payload_len);
	    }
	}
    }
    else if (*type == IP_PROTO_ICMP)
    {
	printf("\t\t{{ Layer 4 :::: ICMP }}\n");
    }
    else if (*type == IP_PROTO_IGMP)
    {
	printf("\t\t{{ Layer 4 :::: IGMP }}\n");
    }
    else if (*type == IPPROTO_UDP)
    {
	struct udp_hdr *uh = (struct udp_hdr*) data;
	printf("\t\t{{  Level 4 ::: User Datagram Protocol  }}\n");
	printf("\t\t{ SrcPort: %5d\tDstPort: %5d }\n",
	       ntohs(uh->sport), ntohs(uh->dport));
	printf("\t\t{ Length: %d\tCheck: %x }\n",
	       ntohs(uh->len), ntohs(uh->chk));
	
	header_len = sizeof(struct udp_hdr);
    }
    else
    {
	fprintf(stderr, "Unknown transport layer protocol %#x", *type);
    }
    return header_len;
}

static void
show_help(const char *exename)
{
    int w = 30;
    printf("Usage: %s [options]\n", exename);
    printf("\t%-*s     %s\n", w, "-i, --interface  <iface>", "Specify which interface to use.");
    printf("\t%-*s     %s\n", w, "-m, --monitor", "Try to set monitor mode (for wireless devices).");
    printf("\t%-*s     %s\n", w, "-p, --promiscuous", "Try to set promiscuous mode.");
    printf("\t%-*s     %s\n", w, "-w, --write <file>", "Dump packets to a file.");
    printf("\t%-*s     %s\n", w, "-r, --file <file>", "Read packets in offline from file.");
    printf("\t%-*s     %s\n", w, "-t, --tee <file>", "Like `-w', but also show packets on the screen.");
    printf("\t%-*s     %s\n", w, "-l, --list-devices", "List available devices for capture.");
    printf("\t%-*s     %s\n", w, "-c, --count <n>", "Analyze only n packets and exit.");
    printf("\t%-*s     %s\n", w, "-v, --verbose", "Set verbose mode.");
    printf("\t%-*s     %s\n", w, "-X, --hexdump", "Show hexdump.");
    printf("\t%-*s     %s\n", w, "-Q, --direction <in|out|inout>", "Set capture direction.");
    printf("\t%-*s     %s\n", w, "-W, --watch-visits <file>", "Watch peer internet activity and log in file.");
    printf("\t%-*s     %s\n", w, "-h, --help", "Show this help message.");
}

static void
parse_options(int argc, char* argv[])
{
    int opt, s;
    opterr = 0;
    while (1)
    {
	static struct option long_options[] = {
	    {"tee",         required_argument, 0, 't'},
	    {"write",       required_argument, 0, 'w'},
	    {"file",        required_argument, 0, 'r'},
	    {"promiscious", no_argument,       0, 'p'},
	    {"monitor",     no_argument,       0, 'm'},
	    {"help",        no_argument,       0, 'h'},
	    {"interface",   required_argument, 0, 'i'},
	    {"list-devices",no_argument,       0, 'l'},
	    {"count",       required_argument, 0, 'c'},
	    {"verbose",     no_argument,       0, 'v'},
	    {"hexdump",     no_argument,       0, 'X'},
	    {"direction",   required_argument, 0, 'Q'},
	    {"watch-visits",no_argument,       0, 'W'},
	    {0,             0,                 0,  0}
	};

	opt = getopt_long(argc, argv, ":t:o:r:i:c:pQ:XW:mKvlh", long_options, NULL);
	if (opt == -1)
	    break;
	
	switch (opt)
	{
	case 'W':
	    flag_visits = 1;
	    watchfile = optarg;
	    break;
	case 'Q':
	    if (!strcmp(optarg, "in"))
		direction = PCAP_D_IN;
	    else if (!strcmp(optarg, "out"))
		direction = PCAP_D_OUT;
	    else if (!strcmp(optarg, "inout"))
		direction = PCAP_D_INOUT;
	    else
		errx(EXIT_FAILURE, "Bad direction specified.");
	    break;
	case 'X':
	    flag_dump++;
	    break;
	case 'v':
	    flag_verbose = 1;
	    break;
	case 't':
	    flag_tee = 1;
	    output_filename = optarg;
	    break;
	case 'w':
	    output_filename = optarg;
	    break;
	case 'r':
	    input_filename = optarg;
	    break;
	case 'p':
	    flag_promisc = 1;
	    break;
	case 'm':
	    flag_monitor = 1;
	    break;
	case 'i':
	    cap_device = optarg;
	    break;
	case 'l':
	    flag_list_dev = 1;
	    break;
	case 'c':
	    packet_num = atoi(optarg);
	    break;
	case 'h':
	    show_help(argv[0]);
	    exit(EXIT_SUCCESS);
	    break;
	case ':':
	    errx(EXIT_FAILURE, "Options `%c' requires an argument", optopt);
	    break;
	default:
	    errx(EXIT_FAILURE, "Unknown option specified. Use `-h' for help.");
	}
    }
    /* Remaining argument will be interpreted, like in the tcpdump(1), as 
       a filter of packets for capture */
    *filter_expression = '\0';
    s = 0;
    
    while (optind < argc)
    {
	if (1 + s + strlen(argv[optind]) >= FILTER_LEN)
	    errx(EXIT_FAILURE, "Filter expression is too long");
	s += strlen(argv[optind]) + 1;
	strcat(filter_expression, " ");
	strcat(filter_expression, argv[optind++]);
    }

    /* Reading saved information from savefile */
    DEBUG("watchfilename is %s", watchfile);
    if (watchfile)
    {
	flag_visits = 1;
	if (!access(watchfile, R_OK))
	{
	    DEBUG("Trying to read visits from file");
	    if (read_visits(watchfile))
		DEBUG("Reading visits from file FAILED!");
	} else
	    log_message(stderr, "Can't read watchfile.");
	atexit(flush_watchfile);
    }
}

static void
flush_watchfile(void)
{
    save_visits(watchfile);
}

static void
signal_handler(int signum)
{
    switch (signum)
    {
    case SIGINT:
	if (dumper_file)
	    pcap_dump_flush(dumper_file);
	if (watchfile)
	    save_visits(watchfile);
	exit(EXIT_SUCCESS);
	break;
    case SIGUSR1:
	if (dumper_file)
	    pcap_dump_flush(dumper_file);
	break;
    case SIGUSR2:
	if (watchfile)
	    save_visits(watchfile);
	break;
    default:
	break;
    }
}
