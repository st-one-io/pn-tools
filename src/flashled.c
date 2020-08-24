/*
  Copyright: (c) 2019-2020, ST-One Ltda., Guilherme Francescon Cittolin <gguilherme.francescon@st-one.io>
  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

#include "flashled.h"

static void
pnt_flashled_print_usage(const char *progname)
{
    fprintf(stderr, "pn-tools %s\n", PNT_VERSION);
    fprintf(stderr, "usage: %s flashled -i <iface> -t <target> [-h] [-v] [-d] [-p] [-c count] [-w <timewait>]\n\n", progname);
    fprintf(stderr, "Search for Profinet devices and print found ones on each line\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "   -h            Show this help\n");
    fprintf(stderr, "   -i iface      The interface on which to send the packet\n");
    fprintf(stderr, "   -t target     The MAC address of the target device\n");
    fprintf(stderr, "   -v            Be verbose\n");
    fprintf(stderr, "   -d            Show debug information\n");
    fprintf(stderr, "   -c count      Amount of flash requests to send (default=%d)\n", PNT_FLASHLED_COUNT);
    fprintf(stderr, "   -w timewait   Amount of time (in ms) to wait between requests (default=%d)\n", PNT_FLASHLED_TIMEWAIT);
}

int pnt_flashled(int argc, char **argv)
{
    char *if_name;
    int if_name_set = 0;
    int if_target_set = 0;
    int do_count = PNT_FLASHLED_COUNT;
    int timewait = PNT_FLASHLED_TIMEWAIT;
    int sock;
    int if_index;
    uint8_t if_addr[ETH_ALEN];
    uint8_t dest_addr[ETH_ALEN];
    char buf[BUF_SIZE];

    {
        int opt;

        while ((opt = getopt(argc, argv, "vdpc:w:i:t:")) != -1)
        {
            switch (opt)
            {
            case 'v':
                pnt_set_verbose_level(PNT_VERBOSE_PRINT);
                break;
            case 'd':
                pnt_set_verbose_level(PNT_VERBOSE_DEBUG);
                break;
            case 'c':
                do_count = atoi(optarg);
                break;
            case 'w':
                timewait = atoi(optarg);
                break;
            case 'i':
                if_name = optarg;
                if_name_set = 1;
                break;
            case 't':
            {
                int mac[ETH_ALEN];

                if (ETH_ALEN != sscanf(optarg,
                                       "%02x:%02x:%02x:%02x:%02x:%02x",
                                       &mac[0],
                                       &mac[1],
                                       &mac[2],
                                       &mac[3],
                                       &mac[4],
                                       &mac[5]))
                {
                    pnt_flashled_print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                for (int i = 0; i < ETH_ALEN; i++)
                    dest_addr[i] = mac[i];

                if_target_set = 1;
            }
            break;
            default: /* '?' */
                pnt_flashled_print_usage(argv[0]);
                return EXIT_FAILURE;
            }
        }
    }

    pnt_print("Parameters: iface[%s] verbose_level[%d] count[%d] timewait[%d] destination[%02x:%02x:%02x:%02x:%02x:%02x]",
              if_name, pnt_get_verbose_level(), do_count, timewait,
              dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3], dest_addr[4], dest_addr[5]);

    if (!if_name_set || !if_target_set)
    {
        pnt_flashled_print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Create the AF_PACKET socket. */
    sock = open_raw_sock(if_name, if_addr, &if_index, 0, 0, 1, 1);
    if (sock < 0)
    {
        //error has already been printed
        return EXIT_FAILURE;
    }

    memset(buf, 0, BUF_SIZE);
    size_t send_len = pnt_dcp_create_flashled_request(buf, if_addr, dest_addr);
    pnt_debug("flashled packet length: %ld", send_len);

    /* Repeat do_count times */
    for (int cnt = 0; cnt < do_count; cnt++)
    {
        if (cnt > 0)
        {
            usleep(timewait * 1e3);
        }
        pnt_debug("send packet cnt %u", cnt);

        /* Send FlashLed request packet */
        {
            struct sockaddr_ll sock_addr;

            sock_addr.sll_ifindex = if_index;
            sock_addr.sll_halen = ETH_ALEN;
            memcpy(sock_addr.sll_addr, dest_addr, ETH_ALEN);

            if (sendto(sock, buf, send_len, 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0)
            {
                perror("Could not send ident request packet");
                close(sock);
                return EXIT_FAILURE;
            }
        }

        // fire and forget, ignore any answer for now
    }

    pnt_debug("finished");
    close(sock);

    return EXIT_SUCCESS;
}