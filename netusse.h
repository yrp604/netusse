#ifndef _NETUSSE_H
#define _NETUSSE_H

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* define some known socket types/domains/protos.
 */
const int socket_types[] = {
    SOCK_DGRAM,
    SOCK_STREAM,
#ifdef SOCK_PACKET
    SOCK_PACKET,
#endif
    SOCK_SEQPACKET,
    SOCK_RDM,
};

const int socket_protos[] = {
    IPPROTO_IP,
    IPPROTO_ICMP,
    IPPROTO_IGMP,
    IPPROTO_IPIP,
    IPPROTO_TCP,
    IPPROTO_EGP,
    IPPROTO_PUP,
    IPPROTO_UDP,
    IPPROTO_IDP,
#ifdef IPPROTO_DCCP
    IPPROTO_DCCP,
#endif
    IPPROTO_RSVP,
    IPPROTO_GRE,
    IPPROTO_IPV6,
    IPPROTO_ESP,
    IPPROTO_AH,
#ifdef IPPROTO_BEETPH
    IPPROTO_BEETPH,
#endif
    IPPROTO_PIM,
#ifdef IPPROTO_COMP
    IPPROTO_COMP,
#endif
#ifdef IPPROTO_SCTP
    IPPROTO_SCTP,
#endif
#ifdef IPPROTO_UDPLITE
    IPPROTO_UDPLITE,
#endif
};

const int socket_domains[] = {
#ifdef         AF_UNSPEC
    AF_UNSPEC,
#endif
#ifdef         AF_UNIX
    AF_UNIX,
#endif
#ifdef         AF_LOCAL
    AF_LOCAL,
#endif
#ifdef         AF_INET
    AF_INET,
#endif
#ifdef         AF_AX25
    AF_AX25,
#endif
#ifdef         AF_IPX
    AF_IPX,
#endif
#ifdef AF_APPLETALK
    AF_APPLETALK,
#endif
#ifdef         AF_NETROM
    AF_NETROM,
#endif
#ifdef         AF_BRIDGE
    AF_BRIDGE,
#endif
#ifdef         AF_ATMPVC
    AF_ATMPVC,
#endif
#ifdef        AF_X25
    AF_X25,
#endif
#ifdef        AF_INET6
    AF_INET6,
#endif
#ifdef        AF_ROSE
    AF_ROSE,
#endif
#ifdef        AF_DECnet
    AF_DECnet,
#endif
#ifdef        AF_NETBEUI
    AF_NETBEUI,
#endif
#ifdef        AF_SECURITY
    AF_SECURITY,
#endif
#ifdef        AF_KEY
    AF_KEY,
#endif
#ifdef        AF_NETLINK
    AF_NETLINK,
#endif
#ifdef        AF_ROUTE
    AF_ROUTE,
#endif
#ifdef        AF_PACKET
    AF_PACKET,
#endif
#ifdef        AF_ASH
    AF_ASH,
#endif
#ifdef        AF_ECONET
    AF_ECONET,
#endif
#ifdef        AF_ATMSVC
    AF_ATMSVC,
#endif
#ifdef        AF_RDS
    AF_RDS,
#endif
#ifdef        AF_SNA
    AF_SNA,
#endif
#ifdef        AF_IRDA
    AF_IRDA,
#endif
#ifdef        AF_PPPOX
    AF_PPPOX,
#endif
#ifdef        AF_WANPIPE
    AF_WANPIPE,
#endif
#ifdef        AF_LLC
    AF_LLC,
#endif
#ifdef        AF_CAN
    AF_CAN,
#endif
#ifdef        AF_TIPC
    AF_TIPC,
#endif
#ifdef        AF_BLUETOOTH
    AF_BLUETOOTH,
#endif
#ifdef        AF_IUCV
    AF_IUCV,
#endif
#ifdef        AF_RXRPC
    AF_RXRPC,
#endif
#ifdef        AF_ISDN
    AF_ISDN,
#endif
#ifdef        AF_PHONET
    AF_PHONET
#endif
};


/* utils.c */
void kernop(int fd);
char *getfile(void);
int getfd(void);
int evilint(void);
uintptr_t evilptr(void);
void dump(unsigned char * data, unsigned int len);
void fuzzer(char *mm, size_t mm_size);
int randfd(void);

#endif
