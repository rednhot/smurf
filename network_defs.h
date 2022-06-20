# ifndef NETWORK_DEFS_H_
# define NETWORK_DEFS_H_

# include <endian.h>
# include <stdint.h>
#include <netinet/in.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;


# define ETHER_ADDR_LEN 6
# define ETHER_HDR_LEN 14

# define ETHER_P_LOOP 0x0060
# define ETHER_P_IP   0x0800
# define ETHER_P_ARP  0x0806

struct mac_addr
{
    u8 addr[ETHER_ADDR_LEN];
} __attribute__((packed)) ;


struct ether_hdr
{
    struct mac_addr dst_addr;
    struct mac_addr src_addr;
    u16 proto;
} __attribute__((packed));


# define IP_HDR_MIN_LEN 20

# define IP_RF_MASK (0x8000)
# define IP_DF_MASK (0x4000)
# define IP_MF_MASK (0x2000)
# define IP_RF(x) ((x) & IP_RF_MASK)
# define IP_DF(x) ((x) & IP_DF_MASK)
# define IP_MF(x) ((x) & IP_MF_MASK)

# define IPTOS_DSCP_MASK (0xfc)
# define IPTOS_ECN_MASK (0x3)
# define IPTOS_DSCP(x) ((x) & IPTOS_DSCP_MASK)
# define IPTOS_ECN(x) ((x) & IPTOS_ECN_MASK)

# define IP_PROTO_ICMP 1
# define IP_PROTO_IGMP 2
# define IP_PROTO_TCP  6
# define IP_PROTO_UDP  17

struct in_addr get_dev_addr(const char *devname);

struct ip_hdr
{
# if BYTE_ORDER == LITTLE_ENDIAN
    u8 h_len: 4;
    u8 ver: 4;
# elif BYTE_ORDER == BIG_ENDIAN
    u8 ver: 4;
    u8 h_len: 4;
# else
#   error "Unknown endianess"
# endif
    u8 tos;
    u16 total_len;
    u16 ident;
    u16 frag_off;
    u8 ttl;
    u8 proto;
    u16 h_check;
    struct in_addr saddr;
    struct in_addr daddr;
} __attribute__((packed));

# define ARP_OP_REQUEST   1
# define ARP_OP_REPLY     2
# define ARP_OP_RREQUEST  3
# define ARP_OP_RREPLY    4
# define ARP_OP_INREQUEST 8
# define ARP_OP_INREPLY   9
# define ARP_OP_NAK       10

struct arp_hdr
{
    u16 hw_type;
    u16 pr_type;
    u8  hw_addr_len;
    u8  pr_addr_len;
    u16 op;
    u8  src_hw_addr[6];
    u8  src_pr_addr[4];
    u8  dst_hw_addr[6];
    u8  dst_pr_addr[4];
} __attribute__((packed));

# define TCP_HDR_MIN_LEN 20

struct tcp_hdr
{
    u16 sport;
    u16 dport;
    u32 seq_num;
    u32 ack_num;
# if BYTE_ORDER == LITTLE_ENDIAN
    u8 ns: 1;
    u8 res1: 3;
    u8 dat_off: 4;    

    u8 fin: 1;
    u8 syn: 1;
    u8 rst: 1;
    u8 psh: 1;
    u8 ack: 1;
    u8 urg: 1;
    u8 ece: 1;
    u8 cwr: 1;
# elif BYTE_ORDER == BIG_ENDIAN
    u8 dat_off: 4;
    u8 res1: 3;
    u8 ns: 1;

    u8 cwr: 1;
    u8 ece: 1;
    u8 urg: 1;
    u8 ack: 1;
    u8 psh: 1;
    u8 rst: 1;
    u8 syn: 1;
    u8 fin: 1;
# else
#   error "Unknown endianess"    
# endif    
    u16 win_sz;
    u16 chk;
    u16 urg_p;
} __attribute__((packed));

struct udp_hdr
{
    u16 sport;
    u16 dport;
    u16 len;
    u16 chk;
} __attribute__((packed));

char* mac_to_ascii(const struct mac_addr mac);

# endif
