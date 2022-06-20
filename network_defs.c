#include "network_defs.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

char*
mac_to_ascii(const struct mac_addr mac)
{
    static char buf[20];
    sprintf(buf, "%02x", mac.addr[0]);
    for (int i = 1; i < ETHER_ADDR_LEN; ++i)
	sprintf(buf+strlen(buf), ":%02x", mac.addr[i]);
    return buf;
}

struct in_addr
get_dev_addr(const char *devname)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;

    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, devname, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
}
