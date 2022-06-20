#include "/home/mathway/prog/util/util.h"
#include "peer.h"
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/socket.h>

struct net_peer
create_peer(struct mac_addr ma, const char *descr)
{
    struct net_peer p;
    memset(&p, 0, sizeof(p));
    memcpy(&p, &ma, 6);
    p.descr = descr;
    return p;
}

int
make_visit(struct net_peer *peer, struct in_addr ip_addr)
{
    struct hostent *he;
    int vis;    
    if (peer->visit_count == MAX_VISITS)
    {
	log_message(stderr,
		    "Limit of visits exceeded for user with mac %s. Ignoring visit.",
		    mac_to_ascii(peer->hw_addr));
	return -1;
    } else
    {
	he = gethostbyaddr(&ip_addr, 4, AF_INET);
	if (he)
	{
	    for (vis = 0; vis < peer->visit_count; ++vis)
		if (!strcmp(peer->visits[vis].hostname, he->h_name))
		    break;
	    if (vis == peer->visit_count)
	    {
		peer->visits[peer->visit_count].count = 1;
		peer->visits[peer->visit_count].hostname = strdup(he->h_name);
		peer->visit_count++;
	    } else
		peer->visits[vis].count++;
	} else
	{
	    struct in_addr ia;
	    for (vis = 0; vis < peer->visit_count; ++vis)
	    {
		inet_aton(peer->visits[vis].hostname, &ia);

		if (!memcmp(&ia, &ip_addr, 4))
		    break;
	    }
	    if (vis == peer->visit_count)
	    {
		peer->visits[peer->visit_count].count = 1;
		peer->visits[peer->visit_count].hostname = strdup(inet_ntoa(ip_addr));
		peer->visit_count++;
	    } else
		peer->visits[vis].count++;
	}

    }
    return 0;
}

extern struct net_peer peers[MAX_PEERS];
extern int peer_count;

int
save_visits(const char *savefile)
{
    FILE *fp = fopen(savefile, "wb");
    if (!fp)
	return errno;
    
    for (int pr = 0; pr < peer_count; ++pr)
    {
	fprintf(fp, "%s\n%s\n", peers[pr].descr, mac_to_ascii(peers[pr].hw_addr));
	for (int vis = 0; vis < peers[pr].visit_count; ++vis)
	{
	    fprintf(fp,
		    "%s\t%u\n",
		    peers[pr].visits[vis].hostname,
		    peers[pr].visits[vis].count);
	}
	fprintf(fp, "\n");
    }
    fclose(fp);
    return 0;
}

int
read_visits(const char *savefile)
{
    FILE *fp = fopen(savefile, "rb");
    char buf[200];
    int s;
    
    if (!fp)
	return errno;
    peer_count = 0;
    while (1)
    {
	char *peer_desc = NULL;
	if (fscanf(fp, " %m[^\n]", &peer_desc) != 1)
	    break;
	if (fscanf(fp, "%s", buf) != 1)
		    break;
	peers[peer_count] = create_peer(*(struct mac_addr*)ether_aton(buf), peer_desc);
	int ok;
	do
	{
	    s = fscanf(fp, "%*c%[^\n]", buf);
	    if (s != 1)
		break;
	    ok = 0;
	    if (sscanf(buf,
		       "%ms",
		       &peers[peer_count].visits[peers[peer_count].visit_count].hostname) != 1)
		break;
	    if (sscanf(buf,
		       "%*s%u",
		       &peers[peer_count].visits[peers[peer_count].visit_count].count) != 1)
		break;
	    peers[peer_count].visit_count++;
	    ok = 1;
	} while (ok);
	peer_count++;
    }
    fclose(fp);
    return 0;
}

void
print_visit_stats(FILE *file)
{
    for (int pr = 0; pr < peer_count; ++pr)
    {
	fprintf(file, "+++++ Peer #%d +++++\n", pr);
	fprintf(file, "%s\n", peers[pr].descr);
	fprintf(file, "%s\n", mac_to_ascii(peers[pr].hw_addr));
	for (int vis = 0; vis < peers[pr].visit_count; ++vis)
	    fprintf(file, "%s\t%u\n",
		    peers[pr].visits[vis].hostname,
		    peers[pr].visits[vis].count);
	puts("");
    }
}
