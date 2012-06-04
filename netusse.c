/*
 * netusse.c - fucking kernel networking stacks destroyer.
 *
 * At least it successfully broke:
 *  FreeBSD
 *  NetBSD
 *  OpenBSD
 *  Solaris
 *  Linux
 *  MACOSX
 *
 * Copyright (c) Clément Lecigne, 2006-2012
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <stropts.h>
#define _GNU_SOURCE
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/un.h>


#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <sys/sendfile.h>
#include <sys/klog.h>
#include <linux/atalk.h>
#include <linux/can.h>
#else
#include <sys/uio.h>
#endif


#if defined(__OpenBSD__)
#include <util.h>
#endif

#include "netusse.h"

#define SEED_FILE "netusse.seed"

/* DEBUG
 */
#define DEBUG 0
FILE *g_debug;
#define debug(fmt, ...) do { if (DEBUG) fprintf(g_debug, fmt, __VA_ARGS__); } while (0)

/* current socket type
 */
int g_socktype;

/* current socket protocol
 */
int g_sockproto;

/* current socket domain
 */
int g_sockdomain;

/* return a random valid socket.
 */
int random_socket(void)
{
    int ret = -1;
    do
    {
#define _SOCKRAND(name) ((rand() % 4) ? rand() % 255 : name[rand()%(sizeof(name)/sizeof(name[0]))]);
        g_sockdomain = _SOCKRAND(socket_domains);
        g_socktype   = _SOCKRAND(socket_types);
        g_sockproto  = _SOCKRAND(socket_protos);
    }
    while ((ret = socket(g_sockdomain, g_socktype, g_sockproto)) < 0);
    debug("socket(%u, %u, %u);\n", g_sockdomain, g_socktype, g_sockproto);
    return ret;
}

#ifdef __FreeBSD__
static void fuzziovec(struct iovec *io, size_t len)
{
    size_t i;

    for (i = 0; i < len; io++, i++)
    {
        io->iov_len = rand() & 255;
        io->iov_base = malloc(io->iov_len);
        if (io->iov_base) fuzzer(io->iov_base, io->iov_len);
    }
}
#endif

#define PAUSE() printf("<PAUSE>\n"), fflush(stdout), getchar();

#ifdef __linux__
/* check for OOPS and suspicious message in dmesg...
 */
#define check linux_check
static void linux_check()
{
    char    buf[2048];
    int     sz;
    if ((sz = klogctl(0x3, buf, 2048)) > -1)
    {
        /* oops */
        if (strstr(buf, "ecx: ") != NULL)
        {
            printf("dmesg [oops]: %s\n", buf);
            PAUSE();
            return;
        }

        /* sk_free: optmem leakage (28 bytes) detected (happened in ipv6 stack). */
        if (strstr(buf, "leakage"))
        {
            printf("dmesg [leakage]: %s\n", buf);
            PAUSE();
            return;
        }

        /* WARNING: at mm/page_alloc.c:2204 __alloc_pages_nodemask+0x7bd/0x890(). */
        if (strstr(buf, "WARNING: at"))
        {
            printf("dmesg [warning]: %s\n", buf);
            PAUSE();
            return;
        }
    }

    return;
}
#else /* TODO: no check for other OSes */
#define check()
#endif

/* fuzzing setsockopt()
 */
void ssoptusse(int s)
{
	uintptr_t   optval;
	int         optlen, optname, level, ret,
                on = rand() % 2,
                tout = 50;

	do
	{
		switch (rand() % 25)
		{
		case 0:
			level = IPPROTO_IPV6;
			break;
		case 1:
			level = SOL_SOCKET;
			break;
		case 2:
		case 3:
		case 4:
            level = g_sockproto;
			break;
        case 5:
        case 6:
            level = g_sockdomain;
            break;
        default:
            level = evilint();
            break;
		}

		if (rand() % 6)
		{
			optlen = evilint();
			optval = evilint();
		}
		else
		{
			optlen = sizeof (int);
			on = rand();
			optval = (uintptr_t)&on;
		}

		if (rand() % 8)
			optname = rand() % 255;
		else
			optname = evilint();

#if 0
		/* execeptions for well know FreeBSD mbufs exhaustion.
		 */
		if (optname == 182 || optname == 202 || optname == 254 || optname == 91 || optname == 25 || optname == IPV6_IPSEC_POLICY || 
				optname == IPV6_FW_ADD || optname == IPV6_FW_FLUSH
				|| optname == IPV6_FW_DEL || optname == IPV6_FW_ZERO || (current_family == AF_INET && optname == 21) || (current_family == AF_INET6 && optname == 21) )
			continue;
#endif
        debug("setsockopt(%u, %u, %u, %u)\n", s, level, optname, optlen);
		ret = setsockopt(s, level, optname, (void *)optval, optlen);
	}
    while(ret == -1 && tout--);
}

/* very weak ioctl() fuzzer
 */
void ioctlusse(int s)
{
    int          req, i, n, ret;
    char         *iav[6];
    unsigned int tout = 20;

    do
    {
        switch (rand() % 8)
        {
            case 0:
            case 1:
                req = rand() & 255;
                break;
            default:
                req = rand();
                break;
        }

        n = rand() % 7;
        for (i = 0; i < n; i++)
        {
            int len = rand() % 1024;
            iav[i] = malloc(len);
            if (iav[i]) fuzzer(iav[i], len);
        }

#define GETIAV(iii) (rand() % 5 == 0) ? (void *)iav[iii] : (void *)evilptr()

        switch (n)
        {
            case 0:
                ret = ioctl(s, req);
                break;
            case 1:
                ret = ioctl(s, req, GETIAV(0));
                break;
            case 2:
                ret = ioctl(s, req, GETIAV(0), GETIAV(1));
                break;
            case 3:
                ret = ioctl(s, req, GETIAV(0), GETIAV(1), GETIAV(2));
                break;
            case 4:
                ret = ioctl(s, req, GETIAV(0), GETIAV(1), GETIAV(2), GETIAV(3));
                break;
            case 5:
                ret = ioctl(s, req, GETIAV(0), GETIAV(1), GETIAV(2), GETIAV(3), GETIAV(4));
                break;
            case 6:
                ret = ioctl(s, req, GETIAV(0), GETIAV(1), GETIAV(2), GETIAV(3), GETIAV(4), GETIAV(5));
                break;
        }

        for (i = 0; i < n; i++)
            free(iav[i]);
    }
    while (ret == -1 && tout--);
}

/* fuzzing getsockname()
 */
void getsocknamusse(int s)
{
    unsigned char   buf[2048], pbuf[2048];
    unsigned int    len2, len = 0;
    int             ret, i;

    memset(&buf, 'A', 2048);
    memset(&pbuf, 'A', 2048);

    for ( i = 0 ; i < 20 ; i++ )
    {
        len2 = len = rand() % 2048;
        ret = getsockname(s, (struct sockaddr *)&buf, (socklen_t *)&len2);
        if (ret >= 0)
        {
            kernop(s);
            getsockname(s, (struct sockaddr *)&pbuf, &len);
            if (memcmp(&buf, &pbuf, len) != 0)
            {
                printf("\nPOSSIBLE LEAK WITH :\n");
                printf("\tgetsockname(sock (%u, %u, %u), buf, &%d)\n", g_sockdomain, g_socktype, g_sockproto, len);
                len = (len < 0 || len > 2048) ? 2048 : len;
                printf("FIRST CALL:\n");
                dump(buf, len);
                printf("SECOND CALL:\n");
                dump(pbuf, len);
                PAUSE();
            }
            break;
        }
    }
}

/* fuzzing getpeername()
 */
void getpeernamusse(int s)
{
    unsigned char   buf[2048], pbuf[2048];
    unsigned int    len = 0;
    int             ret, i;

    memset(&buf, 'A', 2048);
    memset(&pbuf, 'A', 2048);

    for ( i = 0 ; i < 20 ; i++ )
    {
        len = rand() % 2048;
        ret = getpeername(s, (struct sockaddr *)&buf, &len);
        if (ret >= 0 && memcmp(&buf, &pbuf, (len < 0 || len > 2048) ? 2048 : len) != 0)
        {
            kernop(s);
            getpeername(s, (struct sockaddr *)&pbuf, &len);
            if (memcmp(&buf, &pbuf, (len < 0 || len > 2048) ? 2048 : len) != 0)
            {
                printf("\nPOSSIBLE LEAK WITH :\n");
                printf("\tgetpeername(sock (%u, %u, %u), buf, &%d)\n", g_sockdomain, g_socktype, g_sockproto, len);
                len = (len < 0 || len > 2048) ? 2048 : len;
                printf("FIRST CALL:\n");
                dump(buf, len);
                printf("SECOND CALL:\n");
                dump(pbuf, len);
                PAUSE();
            }

            break;
        }
    }
}

/* fuzzing getsockopt()
 */
void gsoptusse(int s)
{
	unsigned char   buf[2048], pbuf[2048], rbuf[2048];
	int             optname, level, ret, tout;
    unsigned int    len;

	tout = 5;

    memset(&buf, 'A', 2048);
    memset(&pbuf, 'A', 2048);
    memset(&rbuf, 'A', 2048);

	do
	{
		optname = rand() % 255;
		len = evilint();
		switch (rand() % 15)
		{
		case 0:
			level = IPPROTO_IPV6;
			break;
		case 1:
			level = SOL_SOCKET;
			break;
		case 2:
		case 3:
		case 4:
            level = g_sockproto;
			break;
        case 5:
        case 6:
            level = g_sockdomain;
            break;
        default:
            level = evilint();
            break;
		}
#if 0
        /*
		 * anti well know FreeBSD mbufs exhaustion.
		 */
		if (optname == 182 || optname == 202 || optname == 254 || optname == 91 || optname == 25 || optname == IPV6_IPSEC_POLICY || 
				optname == IPV6_FW_ADD || optname == IPV6_FW_FLUSH
				|| optname == IPV6_FW_DEL || optname == IPV6_FW_ZERO || (current_family == AF_INET && optname == 21) || (current_family == AF_INET6 && optname == 21) )
			continue;
#endif
		ret = getsockopt(s, level, optname, &buf, &len);
		tout--;
	}
    while (ret == -1 && tout);

    if (ret == -1 || tout == 0)
        return;

#if 0
#ifdef __linux__
    /* linux false positive
     */
    if (len == 104 && optname == 11)
        return;
#endif
#endif

    kernop(s);
    getsockopt(s, level, optname, &pbuf, &len);

    if (buf[0] == 0xc7 || buf[0] == 0xc8 || ( memcmp(&buf, &pbuf, (len < 0 || len > 2048) ? 2048 : len) != 0 && memcmp(&pbuf, &rbuf, (len > 2048) ? 2048 : len) != 0 ))
    {
        printf("\nPOSSIBLE LEAK WITH :\n");
		printf("\tgetsockopt(sock (%u, %u, %u), %d, %u, buf, &%d)\n", g_sockdomain, g_socktype, g_sockproto, level, optname, len);
        len = (len < 0 || len > 2048) ? 2048 : len;
        printf("FIRST CALL:\n");
        dump(buf, len);
        printf("SECOND CALL:\n");
        dump(pbuf, len);
        PAUSE();
    }

	return;
}

/* create fuzzed sockaddr
 */
static void sockaddrfuzz(char *buf, size_t len)
{
    struct sockaddr  *sa     = (struct sockaddr *)buf;
    struct sockaddr_un  *sun    = (struct sockaddr_un *)buf;

    /* mangling
     */
    fuzzer(buf, len);

    if (len < sizeof(struct sockaddr))
        return;

    sa->sa_family = g_sockdomain;

    /* patching
     */
    switch (rand() % 5)
    {
        case 0:
        case 1:
        case 3:
        case 2:
        /* path */
        if (len > 16)
        {
            char *f = getfile();
#define min(a, b) (a < b) ? a : b
            strncpy(sun->sun_path, f, min(strlen(f), len-sizeof(struct sockaddr)));
            break;
        }
        default:
        /* TODO */
        break;
    }
}

/* listen
 */
void listenusse(int s)
{
    listen(s, evilint());
}

/* fucking bind()
 */
void bindusse(int fd)
{
    size_t              len;
    int                 ret = -1, tout = 5;
    char                *b;

    do
    {
        len = evilint() % 4096;
        b = malloc(len);
        if (!b) continue;
        sockaddrfuzz(b, len);
        debug("bind(%d, x, %zu)\n", fd, len);
        ret = bind(fd, (struct sockaddr *)&b, len);
        if (ret && (rand() % 2))
            listen(fd, rand());
        free(b); b = NULL;
    }
    while (ret < 0 && tout--);
}

/* fuzzing connect()
 */
void connectusse(int fd)
{
    int                 ret = -1, tout = 5;
    size_t              len;
    char                *b;

    do
    {
        len = evilint() % 4096;
        b = malloc(len);
        if (!b) continue;
        sockaddrfuzz(b, len);
        debug("connect(%d, x, %zu)\n", fd, len);
        ret = connect(fd, (struct sockaddr *)&b, len);
        if (b) free(b), b = NULL;
    }
    while (ret < 0 && tout--);
}

/* fuzing sendto()
 */
void sendtousse(int fd)
{
    char    *addr, *msg;
    size_t  alen, mlen;
    int     flags = 0;

    alen = evilint() % 4096;
    addr = malloc(alen);
    if (addr) sockaddrfuzz(addr, alen);
    mlen = evilint();
    msg = malloc(mlen);
    if (msg != NULL && mlen < 0xFFFFF) fuzzer(msg, mlen);
    sendto(fd, msg, mlen, flags, (struct sockaddr *)addr, (socklen_t)alen);
    if (addr) free(addr);
    if (msg) free(msg);
}

/* fuzzing sendfile()
 */
#ifdef __linux__
void sendfilusse(int fd)
{
    int i;

    for ( i = 0 ; i < 50 ; i++ )
    {
        off_t   offset;
        size_t  size;
        int     ifd, ofd;

        offset = evilint();
        size = evilint();
        ifd = evilint();
        ofd = evilint();

        switch (rand() % 5)
        {
            case 0:
                ifd = fd;
                break;
            case 1:
                ofd = fd;
                break;
            case 2:
                ifd = ofd = fd;
                break;
            case 3:
                ifd = fd;
                ofd = getfd();
                break;
            case 4:
                ofd = fd;
                ifd = getfd();
                break;
        }

        sendfile(ifd, ofd, &offset, size);
        if (ifd != fd)
            close(ifd);
        if (ofd != fd)
            close(ofd);
    }
}
#elif defined(__FreeBSD__)
void sendfilusse(int fd)
{
    int i;

    for ( i = 0 ; i < 50 ; i++ )
    {
        off_t           offset;
        size_t          size;
        int             ifd, flags;
        struct sf_hdtr  hdtr, *hdtrp;

        offset = evilint();
        size = evilint();
        ifd = evilint();
        flags = rand() % 5;
        hdtrp = NULL;

        /* ifd case
         */
        switch (rand() % 5)
        {
            case 0:
                ifd = fd;
                break;
            case 1:
                ifd = evilint();
                break;
            case 3:
                ifd = fd;
                break;
            case 2:
            case 4:
                ifd = getfd();
                break;
        }

        /* off
         */
        if (rand() % 5 == 2)
            offset = 0;

        /* size
         */
        if (rand() % 5 == 2)
            size = rand() & 0xfff;

        /* flags
         */
        if (rand() % 5 == 2)
            flags = rand();

        /* hdtr
         */
        if (rand() % 5 == 2)
        {
            hdtrp = &hdtr;
            hdtr.hdr_cnt = rand() % 10;
            hdtr.headers = malloc(hdtr.hdr_cnt * sizeof(struct iovec));
            if (hdtr.headers) fuzziovec(hdtr.headers, hdtr.hdr_cnt);
            hdtr.trl_cnt = rand() % 10;
            hdtr.trailers = malloc(hdtr.trl_cnt * sizeof(struct iovec));
            if (hdtr.trailers) fuzziovec(hdtr.trailers, hdtr.trl_cnt);
        }

        sendfile(ifd, fd, offset, size, hdtrp, NULL, flags);
        if (ifd != fd)
            close(ifd);
    }
}
#endif

/* fuzzing recvmsg()
 */
#if defined(__NetBSD__) || defined(__OpenBSD__)
void recvmsgusse(int fd)
{
    char name[1024], ctrl[1024], base[1024], iovb[sizeof(struct iovec)];
    struct iovec iov;
    struct msghdr msg;
    int i;

    for ( i = 0 ; i < 50 ; i++ )
    {
        fuzzer(name, 1024);
        fuzzer(base, 1024);
        fuzzer(ctrl, 1024);
        fuzzer(iovb, sizeof(struct iovec));
        msg.msg_name    = name;
        msg.msg_namelen = evilint();
        msg.msg_iovlen  = evilint();
        msg.msg_flags   = rand() & 255;
        msg.msg_iov     = iovb;
        if (rand() % 3)
        {
            msg.msg_iov     = &iov;
            msg.msg_iovlen  = 1;
            iov.iov_base    = base;
            iov.iov_len     = evilint();
        }
        else if (rand() % 5 == 0)
            msg.msg_iov = NULL;
        msg.msg_control = ctrl;
        msg.msg_controllen = evilint();
        debug("recvmsg(%d, {nl = %x, iol = %x, ctl = %x}, 0);\n", fd, msg.msg_namelen, msg.msg_iovlen, msg.msg_controllen);
        recvmsg(fd, &msg, MSG_DONTWAIT);
    }
    return;
}
#elif defined(__linux__) || defined(__FreeBSD__)
void recvmsgusse(int fd)
{
	struct msghdr   msg;
	struct cmsghdr  *cmsg = NULL;
	struct iovec    iov;
    char            *b = NULL;
    int             i;

    for ( i = 0 ; i < 50 ; i++ )
    {
        msg.msg_controllen = (rand() % 50) ? rand() & 0xFFFF : 0;
        if (msg.msg_controllen)
        {
            if (msg.msg_controllen < sizeof (struct cmsghdr))
                cmsg = (struct cmsghdr *)malloc(sizeof (struct cmsghdr));
            else
                cmsg = (struct cmsghdr *)malloc(msg.msg_controllen);
            if (cmsg == NULL) goto nocmsghdr;
            msg.msg_control = cmsg;
            fuzzer((char *)cmsg, min(sizeof (struct cmsghdr), msg.msg_controllen));
            if (rand() % 10 == 0)
            {
                cmsg->cmsg_level = (rand() % 2) ? IPPROTO_IP : evilint();
                cmsg->cmsg_type = (rand() % 2) ? rand() % 255 : evilint();
                cmsg->cmsg_len = (rand() % 2) ? msg.msg_controllen : evilint();
            }
        }
        else
        {
nocmsghdr:
            msg.msg_control = (rand() % 5) ? NULL : (void*)evilptr();
            msg.msg_controllen = (rand() % 2) ? rand() : 0;
        }
        iov.iov_len = (rand() % 2) ? evilint() : 1;
        iov.iov_base = ((rand() % 5) == 0) ? (void*)evilptr() : &msg;
        msg.msg_iov = ((rand() % 5) == 0) ? (void*)evilptr() : &iov;
        if (rand() % 10)
        {
            msg.msg_namelen = evilint() & 4096;
            b = malloc(msg.msg_namelen);
            if (b != NULL && msg.msg_namelen < 0xFFFFF) fuzzer(b, msg.msg_namelen);
            msg.msg_name = b;
        }
        else
        {
            msg.msg_name = (caddr_t)evilptr();
            msg.msg_namelen = evilint();
        }
        msg.msg_flags = evilint();
        debug("recvmsg(%d, {nl = %x, iol = %zx, ctl = %zx}, 0);\n", fd, msg.msg_namelen, msg.msg_iovlen, msg.msg_controllen);
        recvmsg(fd, &msg, MSG_DONTWAIT);
        free(cmsg);
        cmsg = NULL;
        free(b);
        b = NULL;
    }
}
#endif


/* fuzzing sendmsg()
 */
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
void sendmsgusse(int fd)
{
    char name[1024], ctrl[1024], base[1024], iovb[sizeof(struct iovec)], *b = NULL, *bb = NULL;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    int i;

    for ( i = 0 ; i < 50 ; i++ )
    {
        msg.msg_controllen = (rand() % 50) ? rand() : 0;
        if (msg.msg_controllen)
        {
            b = malloc(CMSG_SPACE(msg.msg_controllen % 5000));
            if (b == NULL) continue;
            fuzzer(b, CMSG_SPACE(msg.msg_controllen % 5000));
            msg.msg_control = b;
            msg.msg_controllen = CMSG_SPACE(msg.msg_controllen % 5000);
            cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_len = CMSG_LEN(msg.msg_controllen);
            cmsg->cmsg_type = (rand() % 2) ? rand() % 255 : evilint();
            cmsg->cmsg_len = (rand() % 2) ? msg.msg_controllen : evilint();
        }
        else
        {
nocmsghdr:
            msg.msg_control = (rand() % 5) ? NULL : (void*)evilint();
            msg.msg_controllen = (rand() % 2) ? rand() : 0;
        }

        if ((rand() % 5) == 0)
        {
            iov.iov_len = (rand() % 2) ? evilint() : 1;
            iov.iov_base = ((rand() % 5) == 0) ? (void*)evilint() : &msg;
            msg.msg_iov = ((rand() % 5) == 0) ? (void*)evilint() : &iov;
            if (rand() % 10)
            {
                msg.msg_namelen = evilint() & 4096;
                bb = malloc(msg.msg_namelen);
                if (bb != NULL && msg.msg_namelen < 0xFFFFF) fuzzer(bb, msg.msg_namelen);
                msg.msg_name = bb;
            }
            else
            {
                msg.msg_name = (caddr_t)evilint();
                msg.msg_namelen = evilint();
            }
            msg.msg_flags = evilint();
        }
        debug("sendmsg(%d, {nl = %x, iol = %x, ctl = %x}, 0);\n", fd, msg.msg_namelen, msg.msg_iovlen, msg.msg_controllen);
        sendmsg(fd, &msg, MSG_DONTWAIT);
        if (b) free(b);
        if (bb) free(bb);
        b = NULL;
        bb = NULL;
    }

    return;
}
#elif defined(__linux__)
void sendmsgusse(int fd)
{
	struct msghdr   msg;
	struct cmsghdr  *cmsg = NULL;
	struct iovec    iov;
    char            *b = NULL, *bb = NULL;
    int             i;

    for ( i = 0 ; i < 50 ; i++ )
    {
        msg.msg_controllen = (rand() % 50) ? rand() : 0;
        if (msg.msg_controllen)
        {
            b = malloc(CMSG_SPACE(msg.msg_controllen % 5000));
            if (b == NULL) goto nocmsghdr;
            fuzzer(b, CMSG_SPACE(msg.msg_controllen % 5000));
            msg.msg_control = b;
            msg.msg_controllen = CMSG_SPACE(msg.msg_controllen % 5000);
            cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_len = CMSG_LEN(msg.msg_controllen);
            cmsg->cmsg_type = (rand() % 2) ? rand() % 255 : evilint();
            cmsg->cmsg_len = (rand() % 2) ? msg.msg_controllen : evilint();
        }
        else
        {
nocmsghdr:
            msg.msg_control = (rand() % 5) ? NULL : (void *)evilptr();
            msg.msg_controllen = (rand() % 2) ? rand() : 0;
        }

        if ((rand() % 5) == 0)
        {
            iov.iov_len = (rand() % 2) ? evilint() : 1;
            iov.iov_base = ((rand() % 5) == 0) ? (void*)evilptr() : &msg;
            msg.msg_iov = ((rand() % 5) == 0) ? (void*)evilptr() : &iov;
            if (rand() % 10)
            {
                msg.msg_namelen = evilint() & 4096;
                bb = malloc(msg.msg_namelen);
                if (bb != NULL && msg.msg_namelen < 0xFFFFF) fuzzer(bb, msg.msg_namelen);
                msg.msg_name = bb;
            }
            else
            {
                msg.msg_name = (caddr_t)evilptr();
                msg.msg_namelen = evilint();
            }
            msg.msg_flags = evilint();
        }

        sendmsg(fd, &msg, MSG_DONTWAIT);
        if (b) free(b);
        if (bb) free(bb);
        b = NULL;
        bb = NULL;
    }
}

/* fuzzing splice()
 */
void splicusse(int fd)
{
    unsigned int    flags;
    off_t           offin, offout;
    size_t          len;
    int             pipes[2], fdout;

    fdout = fd;
    if (rand() % 3)
    {
        if (pipe(pipes) == 0)
            fdout = pipes[rand() % 2];
    }

    switch (rand() % 5)
    {
        case 0:
            flags = evilint();
            break;
        default:
            flags = evilint() % 8;
            break;
    }

    switch (rand() % 5)
    {
        case 0:
            offin = evilint();
            offout = evilint();
            break;
        default:
            offin = offout = 0;
            break;
    }

    switch (rand() % 5)
    {
        case 0:
            len = evilint();
            break;
        default:
            len = evilint() % 128;
            break;
    }

    splice(fd, offin, fdout, offout, len, flags);
}
#endif

/* fuzzing mmap
 */
void mmapusse(int fd)
{
    void    *addr, *raddr;
    int     flags, prot;
    size_t  len, off;

    switch (rand() % 5)
    {
        case 0:
            flags = evilint();
            prot  = evilint();
            break;
        default:
            flags = evilint() % 0x20;
            prot = evilint() % 0x4;
            break;
    }

    switch (rand() % 5)
    {
        case 0:
            addr = (void *)evilptr();
            flags |= MAP_FIXED;
            break;
        default:
            addr = NULL;
            flags &= ~MAP_FIXED;
            break;
    }

    raddr = mmap(addr, (len=evilint()), prot, flags, fd, (off=evilint()));

    if (raddr != MAP_FAILED)
        munmap(addr, len);
}

void usage(char *prog)
{
	printf("\tusage: %s [-r seed][-n occ][-o occ][-f]\n", prog);
    printf("Read the sources for further information... :-)\n");
	exit(EXIT_FAILURE);
}

#ifdef __linux__
struct foo_ip_mreq_source
{
   __u32 imr_multiaddr;
   __u32 imr_interface;
   __u32 imr_sourceaddr;
};
#endif

/* do some interesting valid operation on the socket.
 */
void valid_op(int s)
{
    struct ip_mreqn mr;
#ifdef __linux__
    struct foo_ip_mreq_source ms;
#endif
    int             val = 1, flags;
    unsigned char   ttl = rand() % 255;
#ifdef __linux__
    char   *dev = (rand() % 2) ? "eth0" : "wlan0";
#else
    char   *dev = "lo0";
#endif

    /* non-blocking sock */
    flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);

#ifdef __linux__
    /* multicast stuffs from Paul Starzetz sploits. */
    if (rand() % 5 == 0)
    {
        memset (&mr, 0, sizeof (mr));
        mr.imr_multiaddr.s_addr = inet_addr ("224.0.0.199");
        setsockopt (s, SOL_IP, IP_ADD_MEMBERSHIP, &mr, sizeof (mr));
        memset (&ms, 0, sizeof (ms));
        ms.imr_multiaddr = inet_addr ("224.0.0.199");
        ms.imr_sourceaddr = inet_addr ("4.5.6.7");
        setsockopt (s, SOL_IP, IP_BLOCK_SOURCE, &ms, sizeof (ms));
        memset (&ms, 0, sizeof (ms));
        ms.imr_multiaddr = inet_addr ("224.0.0.199");
        ms.imr_sourceaddr = inet_addr ("4.5.6.7");
        setsockopt (s, SOL_IP, IP_UNBLOCK_SOURCE, &ms, sizeof (ms));
        memset (&ms, 0, sizeof (ms));
        ms.imr_multiaddr = inet_addr ("224.0.0.199");
        ms.imr_sourceaddr = inet_addr ("4.5.6.7");
        setsockopt (s, SOL_IP, IP_UNBLOCK_SOURCE, &ms, sizeof (ms));
        memset (&ms, 0, sizeof (ms));
        ms.imr_multiaddr = inet_addr ("224.0.0.199");
        ms.imr_sourceaddr = inet_addr ("4.5.6.7");
        setsockopt (s, SOL_IP, IP_UNBLOCK_SOURCE, &ms, sizeof (ms));
    }
#endif

#if 0
    /* sctp shits. */
    l = sizeof(sctp_initmsg);
    getsockopt(s, SOL_SCTP, SCTP_INITMSG, &msg, &l);
    msg.sinit_num_ostreams = evilint();
    msg.sinit_max_instreams = evilint();
    setsockopt(s, SOL_SCTP, SCTP_INITMSG, &msg, sizeof(struct sctp_initmsg));
    setsockopt(s, SOL_SCTP, SCTP_NODELAY, (char*)&val, sizeof(val));
#endif

    /* rand sock stuffs. */
    if (rand() % 5 == 0) setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&val, sizeof(val));
    if (rand() % 5 == 0) setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&val, sizeof(val));
#ifdef SO_REUSEPORT
    if (rand() % 5 == 0) setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (char *)&val, sizeof(val));
#endif
    if (rand() % 5 == 0) setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&val, sizeof(val));
    if (rand() % 5 == 0) setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof(ttl));
#ifdef TCP_NOPUSH
    if (rand() % 5 == 0) setsockopt(s, IPPROTO_TCP, TCP_NOPUSH, (char *)&val, sizeof(val));
#endif
    if (rand() % 5 == 0) setsockopt(s, IPPROTO_IP, IP_PKTINFO, (char *)&val, sizeof(val));
	if (rand() % 5 == 0) val = evilint(), setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&val, sizeof(val));
	if (rand() % 5 == 0) val = evilint(), setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&val, sizeof(val));
	if (rand() % 5 == 0) val = evilint(), setsockopt(s, SOL_SOCKET, SO_SNDLOWAT, (char *)&val, sizeof(val));
	if (rand() % 5 == 0) val = evilint(), setsockopt(s, SOL_TCP, TCP_MAXSEG, (char *)&val, sizeof(val));

#ifdef __linux__
    if (rand() % 5 == 0) setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, 4);
#endif

    /* TODO: add FreeBSD multicast/ipv6/sctp stuffs :) */

    return;
}

typedef void (*randop_t)(int);

/* do an interesting random operation on the socket
 */
void random_op(int s)
{
    randop_t randops[] = {
        &ssoptusse,
        &ioctlusse,
        &gsoptusse,
        &sendmsgusse,
        &recvmsgusse,
        &sendtousse,
        &sendfilusse,
        &bindusse,
        &listenusse,
        &connectusse,
        &splicusse,
        &sendtousse,
        //&getsocknamusse,
        &getpeernamusse,
        &mmapusse,
    };
    randops[rand()%sizeof(randops)/sizeof(randops[0])](s);
}

int main(int ac, char **av)
{
	char            c;
	int             s, i;
	unsigned int    seed, occ, opts;

    /* init */
    g_debug = stdout;
	seed = getpid() ^ time(NULL);
	occ = 5000000;
	opts = 50;

    /* (gdb) handle SIGPIPE nostop noprint pass */
    signal(SIGPIPE, SIG_IGN);

    /* arg parsing */
	while ((c = getopt(ac, av, "r:o:n:f")) != EOF)
	{
		switch (c)
		{
		case 'r':
			seed = atoi(optarg);
			break;
		case 'o':
			opts = atoi(optarg);
			break;
		case 'n':
			occ = atoi(optarg);
			break;
        case 'f':
            s = open(SEED_FILE, O_RDONLY);
            if (s > 0)
            {
                read(s, &seed, sizeof(seed));
                close(s);
            }
            break;
		case 'h':
			usage(av[0]);
			break;
		default:
			usage(av[0]);
			break;
		}
	}

    /* seeding */
	printf(" + using seed: %u\n", seed);
    s = open(SEED_FILE, O_WRONLY|O_CREAT, 0666);
    if (s > 0)
    {
        write(s, &seed, sizeof(seed));
        close(s);
    }
	srand(seed);

    /* vroum! */
	while (occ--)
	{
        s = random_socket();
        valid_op(s);
		for (i = 0; i < opts; i++) random_op(s);
		close(s);
        check();
        if (!DEBUG) printf("."), fflush(stdout);
	}

	exit(EXIT_SUCCESS);
}
