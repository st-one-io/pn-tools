/*
  Copyright: (c) 2019, Guilherme Francescon Cittolin <gfcittolin@gmail.com>
  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

#include "discovery.h"

    static void
    pnt_discovery_print_usage(const char *progname)
{
    fprintf(stderr, "pntools %s\n", PNT_VERSION);
    fprintf(stderr, "usage: %s discovery -i <iface> [-v] [-d] [-h] [-p] [-t <timeout>]\n\n", progname);
    fprintf(stderr, "Search for Profinet devices and print found ones on each line\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "   -h          Show this help\n");
    fprintf(stderr, "   -i iface    The interface on which devices will be searched for\n");
    fprintf(stderr, "   -v          Be verbose\n");
    fprintf(stderr, "   -d          Show debug information\n");
    fprintf(stderr, "   -o          Print the header of fields \n");
    fprintf(stderr, "   -p          Put the interface in promiscuous mode\n");
    fprintf(stderr, "   -t timeout  Amount of time (in ms) to wait for devices (default=%d)\n", PNT_DISCOVERY_TIMEOUT);
}

int pnt_discovery(int argc, char **argv)
{
    char *if_name;
    int if_name_set = 0;
    int do_headers = 0;
    int do_promiscuous = 0;
    int timeout = PNT_DISCOVERY_TIMEOUT;
    int sock;
    int if_index;
    uint8_t if_addr[ETH_ALEN];
    uint8_t dest_addr[ETH_ALEN];
    char buf[BUF_SIZE];

    memcpy(dest_addr, addr_broadcast_pn, ETH_ALEN);

    {
        int opt;

        while ((opt = getopt(argc, argv, "vdot:i:")) != -1)
        {
            switch (opt)
            {
            case 'v':
                pnt_set_verbose_level(PNT_VERBOSE_PRINT);
                break;
            case 'd':
                pnt_set_verbose_level(PNT_VERBOSE_DEBUG);
                break;
            case 'o':
                do_headers = 1;
                break;
            case 'p':
                do_promiscuous = 1;
                break;
            case 't':
                timeout = atoi(optarg);
                break;
            case 'i':
                if_name = optarg;
                if_name_set = 1;
                break;
            default: /* '?' */
                pnt_discovery_print_usage(argv[0]);
                return EXIT_FAILURE;
            }
        }
    }

    pnt_print("Parameters: iface[%s] verbose_level[%d] headers[%d] promiscuous[%d] timeout[%d]",
              if_name, pnt_get_verbose_level(), do_headers, do_promiscuous, timeout);

    if (!if_name_set)
    {
        pnt_discovery_print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Create the AF_PACKET socket. */
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("Cannot open socket");
        return EXIT_FAILURE;
    }
    pnt_debug("socket open fd %p", sock);

    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    /* Get the index number and MAC address of ethernet interface. */
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("Cannot get interface number");
        close(sock);
        return EXIT_FAILURE;
    }
    if_index = ifr.ifr_ifindex;
    pnt_debug("interface number is %d", if_index);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("Cannot get interface address");
        close(sock);
        return EXIT_FAILURE;
    }
    memcpy(if_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    pnt_debug("interface address is %02x:%02x:%02x:%02x:%02x:%02x",
              if_addr[0], if_addr[1], if_addr[2], if_addr[3], if_addr[4], if_addr[5]);

    if (do_promiscuous)
    {
        /* Set interface to promiscuous mode. */
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
        {
            perror("Cannot get interface flags");
            close(sock);
            return EXIT_FAILURE;
        }
        ifr.ifr_flags |= IFF_PROMISC;
        if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
        {
            perror("Cannot set interface flags");
            close(sock);
            return EXIT_FAILURE;
        }
        pnt_debug("interface's promiscuous mode set");
    }

    // set socket to non-blocking
    {
        int flags;
        flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0)
        {
            perror("Cannot get socket flags");
            close(sock);
            return EXIT_FAILURE;
        }
        flags |= O_NONBLOCK;
        fcntl(sock, F_SETFL, flags);
    }

    /* Allow the socket to be reused. */
    int s = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &s, sizeof(s)) < 0)
    {
        perror("Cannot set SO_REUSEADDR on socket");
        close(sock);
        return EXIT_FAILURE;
    }
    pnt_debug("SO_REUSEADDR set");

    /* Bind to device. */
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ - 1) < 0)
    {
        perror("Cannot bind to interface");
        close(sock);
        return EXIT_FAILURE;
    }
    pnt_debug("SO_BINDTODEVICE set");

    /* Send IdentRequest packet */
    {
        memset(buf, 0, BUF_SIZE);

        size_t send_len = pnt_dcp_create_ident_request(buf, if_addr);

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

    if (do_headers)
    {
        printf("Station Name\tVendor Value\tDevice Role\tVendorID\tDeviceID\tIP Address\tSubnet Mask\tGateway\tIP status\n");
    }

    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    memcpy(&end, &start, sizeof(start));
    for (; TIME_DIFF_MS(start, end) < timeout; clock_gettime(CLOCK_MONOTONIC, &end))
    {
        ssize_t received;

        received = recvfrom(sock, buf, BUF_SIZE, 0, NULL, NULL);
        if (received <= 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                usleep(10000);
                continue;
            }
            else
            {
                pnt_debug("recvfrom empty read");
                break;
            }
        }

        if (pnt_get_verbose_level() >= PNT_VERBOSE_DEBUG)
        {
            struct ether_header *eh = (struct ether_header *)buf;
            fprintf(stderr, "\ndebug: recv: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x (%04x)",
                    eh->ether_shost[0],
                    eh->ether_shost[1],
                    eh->ether_shost[2],
                    eh->ether_shost[3],
                    eh->ether_shost[4],
                    eh->ether_shost[5],
                    eh->ether_dhost[0],
                    eh->ether_dhost[1],
                    eh->ether_dhost[2],
                    eh->ether_dhost[3],
                    eh->ether_dhost[4],
                    eh->ether_dhost[5],
                    ntohs(eh->ether_type));
        }

        struct pn_dcp_header *pn_dcp = pnt_get_dcp_header(buf, received, if_addr, PN_FRAME_ID_RTA_DCP_RESPONSE);
        if (pn_dcp == NULL)
            continue;

        struct pn_dcp_identify_response_data pn_dcp_data;
        memset(&pn_dcp_data, 0, sizeof(pn_dcp_data));
        pnt_parse_dcp_response_blocks(pn_dcp, &pn_dcp_data);

        printf("%s\t%s\t%u\t%04x\t%04x\t%u.%u.%u.%u\t%u.%u.%u.%u\t%u.%u.%u.%u\t%u\n",
               pn_dcp_data.device_stationname,
               pn_dcp_data.device_vendorvalue,
               pn_dcp_data.device_role,
               pn_dcp_data.device_id_vendor,
               pn_dcp_data.device_id_device,
               pn_dcp_data.device_ip_addr[0],
               pn_dcp_data.device_ip_addr[1],
               pn_dcp_data.device_ip_addr[2],
               pn_dcp_data.device_ip_addr[3],
               pn_dcp_data.device_ip_mask[0],
               pn_dcp_data.device_ip_mask[1],
               pn_dcp_data.device_ip_mask[2],
               pn_dcp_data.device_ip_mask[3],
               pn_dcp_data.device_ip_gateway[0],
               pn_dcp_data.device_ip_gateway[1],
               pn_dcp_data.device_ip_gateway[2],
               pn_dcp_data.device_ip_gateway[3],
               pn_dcp_data.device_ip_info);
    }

    close(sock);

    return EXIT_SUCCESS;
}