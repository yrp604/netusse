#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

/* do a random kernel operation, used to detect memory disclosure.
 */
void kernop(int fd)
{
    /* stolen from Jon Oberheide sploits
    */
#ifdef __linux__
    const int   randcalls[] = {
        __NR_getitimer, __NR_getpid,
        __NR_getdents, __NR_getcwd, 
        __NR_getrlimit, __NR_getuid, __NR_getgid, __NR_geteuid, __NR_getegid,
        __NR_getppid, __NR_getpgrp, __NR_getgroups,
        __NR_getpgid, __NR_getsid, 
    };
#endif
    const int       randsopts[] = { SOL_SOCKET };
    int             ret, o;
    unsigned int    len;
    char            buf[1024];

    do
    {
        switch ( rand() % 2 )
        {
#ifdef __linux__
            case 0:
                o = randcalls[rand() % sizeof(randcalls)/sizeof(randcalls[0])];
                ret = syscall(o);
                break;
#else
            case 0: /* TODO: to bored to enumerate unevil syscall on other sys. */
#endif
            case 1:
            default:
                len = (rand() % 2) ? sizeof(int) : sizeof(buf);
                ret = getsockopt(fd, randsopts[rand() % sizeof(randsopts)/sizeof(randsopts[0])], rand() % 130, &buf, &len);
                break;
        }
    }
    while ( ret < 0 );
}

/* return random filename on the FS or not.
 */
char *getfile(void)
{
    switch (rand() % 5)
    {
        case 0:
            return "/etc/passwd";
        case 1:
            return "/dev/random";
        case 2:
            return "/tmp/fusse";
        case 3:
            return "/tmp/";
#ifdef __linux__
        case 4:
            return "/proc/self/maps";
#endif
        default:
            return "/";
    }
    return "foo";
}

/* in netusse.c and used here, crap++
 */
int random_socket(void);

/* return a random file descriptor
 */
int getfd(void)
{
    int fd, flags;

    do {
        switch (rand() % 7)
        {
            case 0:
                fd = open("/etc/passwd", O_RDONLY);
                break;
            case 1:
                fd = random_socket();
                break;
            case 2:
                fd = open("/dev/random", O_RDONLY);
                break;
            case 3:
                fd = open("/tmp/fusse", O_CREAT|O_RDWR, 0666);
                break;
            default:
                fd = open(getfile(), rand());
                break;
        }
    }
    while (fd < 0);
    flags = fcntl(fd, F_GETFL, 0);
    /* force non blocking more on fd
     */
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

/* return an int from hell! :)
 */
int evilint(void)
{
    int         state;
    unsigned    common_sizeofs[] = { 16, 32, 64, 128, 256 };
#define _SIZEOFRAND ((rand() % 4) ? 1 : common_sizeofs[rand()%(sizeof(common_sizeofs)/sizeof(common_sizeofs[0]))]);
    state = rand() % 20;
    switch ( state )
    {
        case 0:
            return rand();
            break;
        case 1:
            return( 0xffffff00 | (rand() % 256));
        case 2: return 0x8000 / _SIZEOFRAND;
        case 3: return 0xffff / _SIZEOFRAND;
        case 4: return 0x80000000 / _SIZEOFRAND;
        case 5: return -1;
        case 6: return 0xff;
        case 7: return 0x7fffffff / _SIZEOFRAND;
        case 8: return 0;
        case 9: return 4;
        case 10: return 8;
        case 11: return 12;
        case 12: return 0xffffffff / _SIZEOFRAND
        case 13:
        case 14:
                 return rand() & 256;
        default:
                return rand();

    }
}

uintptr_t evilptr(void)
{
    return (uintptr_t) evilint();
}

void dump(unsigned char * data, unsigned int len)
{
    unsigned int dp, p;
    const char trans[] =
        "................................ !\"#$%&'()*+,-./0123456789"
        ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
        "nopqrstuvwxyz{|}~...................................."
        "....................................................."
        "........................................";

    printf("\n");
    for ( dp = 1; dp <= len; dp++ )
    {
        printf("%02x ", data[dp-1]);
        if ( (dp % 8) == 0 )
        {
            printf("| ");
            p = dp;
            for ( dp -= 8; dp < p; dp++ ) {
                printf("%c", trans[data[dp]]);
            }
            printf("\n");
        }
    }

    return;
}

/* create a random stream of mm_size bytes inside mm.
 */
void fuzzer(char *mm, size_t mm_size)
{
    size_t i;

    for ( i = 0 ; i < mm_size ; i++ )
    {
        /* lame format string checker, evil values or random.
         */
        if ( rand() % 40 == 0 && i < mm_size - 2 )
        {
            mm[i++] = '%';
            switch (rand() % 2)
            {
                case 0:
                    mm[i] = 'n';
                    break;
                case 1:
                    mm[i] = 'x';
                    break;
                default:
                    mm[i] = 'u';
                    break;
            }
        }
        else if ( rand() % 40 == 0 )
            mm[i] = 255;
        else if ( rand() % 40 == 0 )
            mm[i] = 0;
        else
        {
            mm[i] = rand() & 255;
            if ( rand() % 10 == 0 )
                mm[i] |= 0x80;
        }
    }

    return;
}

/* return a valid random fd
 */
int randfd(void)
{
    DIR             *dip;
    struct dirent   *dit;
    static int      nbf = 1500;
    unsigned int    n = rand() % nbf, i = 0;
    int             fd = -1;

    chdir("/dev");
    dip = opendir("/dev");
    if ( dip == NULL )
        return -1;

    while ( (dit = readdir(dip)) != NULL )
    {
        if ( i == n )
        {
            //printf("open(%s)...", dit->d_name);
            switch (rand() % 3)
            {
#if defined(__OpenBSD__)
                case 1:
                fd = opendev(dit->d_name, O_RDONLY, (rand() % 2) ? OPENDEV_BLCK : OPENDEV_PART, NULL);
                break;
                case 2:
                fd = opendev(dit->d_name, O_RDWR, (rand() % 2) ? OPENDEV_BLCK : OPENDEV_PART, NULL);
                break;
#else
                case 1:
                case 2:
#endif
                case 0:
                fd = open(dit->d_name, O_RDONLY);
                break;
            }
            //printf("%s\n", (fd > 0) ? "done" : "failed");
            closedir(dip);
            return fd;
        }
        i++;
    }
    nbf = i;

    closedir(dip);
    return -1;
}

