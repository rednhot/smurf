# ifndef PEER_H_
# define PEER_H_

# include "network_defs.h"
# include <stdio.h>

# define MAX_PEERS 256
# define MAX_VISITS 500


struct visit
{
    const char *hostname;
    u32 count;
};

struct net_peer
{
    struct mac_addr hw_addr;
    const char *descr;
    struct visit visits[MAX_VISITS];
    int visit_count;
};

/* Create a peer */
struct net_peer create_peer(struct mac_addr ma, const char *descr);

/* Increment visit count for host from a peer */
int make_visit(struct net_peer *peer, struct in_addr ip_addr);

/* Save info about visits to file */
int save_visits(const char *savefile);

/* Read info about visits from file */
int read_visits(const char *savefile);

/* Shows info about peers on the network */
void print_visit_stats(FILE *file);
# endif
