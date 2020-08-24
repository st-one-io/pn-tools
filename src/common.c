/*
  Copyright: (c) 2019-2020, ST-One Ltda., Guilherme Francescon Cittolin <gguilherme.francescon@st-one.io>
  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

#include "common.h"

static int pnt_verbose_level = 0;

void pnt_set_verbose_level(int lvl)
{
    pnt_verbose_level = lvl;
}

int pnt_get_verbose_level()
{
    return pnt_verbose_level;
}

void pnt_debug(const char *format, ...)
{
    if (pnt_verbose_level < PNT_VERBOSE_DEBUG)
        return;

    va_list args;
    va_start(args, format);

    fputs("debug: ", stderr);
    vfprintf(stderr, format, args);
    fputs("\n", stderr);

    va_end(args);
}

void pnt_print(const char *format, ...)
{
    if (pnt_verbose_level < PNT_VERBOSE_PRINT)
        return;

    va_list args;
    va_start(args, format);

    vfprintf(stderr, format, args);
    fputs("\n", stderr);

    va_end(args);
}

void dump_buffer(char *buf, unsigned int length)
{
    fprintf(stderr, "Dump %u bytes at %p:\n", length, buf);
    for (unsigned int i = 0; i < length; i += 16)
    {
        fprintf(stderr, "%08x:", i);
        for (unsigned int j = i; j < length && (j - i) < 16; j++)
        {
            fprintf(stderr, " %02x", (u_int8_t)buf[j]);
        }
        fprintf(stderr, "\n");
    }
}

// ------------------------------------

int open_raw_sock(char *if_name, uint8_t *if_addr, int *if_index,
                  int do_promiscuous, int non_block, int reuse, int bind_device)
{
    /* Create the AF_PACKET socket. */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("Cannot open socket");
        return -1;
    }
    pnt_debug("open_raw_sock: open fd: %d", sock);

    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    /* Get the index number and MAC address of ethernet interface. */
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("Cannot get interface number");
        close(sock);
        return -1;
    }
    *if_index = ifr.ifr_ifindex;
    pnt_debug("open_raw_sock: iface index: %d", *if_index);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("Cannot get interface address");
        close(sock);
        return -1;
    }
    memcpy(if_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    pnt_debug("open_raw_sock: iface addr: %02x:%02x:%02x:%02x:%02x:%02x",
              if_addr[0], if_addr[1], if_addr[2], if_addr[3], if_addr[4], if_addr[5]);

    if (do_promiscuous)
    {
        /* Set interface to promiscuous mode. */
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
        {
            perror("Cannot get interface flags");
            close(sock);
            return -1;
        }
        ifr.ifr_flags |= IFF_PROMISC;
        if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
        {
            perror("Cannot set interface flags");
            close(sock);
            return -1;
        }
        pnt_debug("open_raw_sock: IFF_PROMISC set");
    }

    if (non_block)
    {
        int flags;
        flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0)
        {
            perror("Cannot get socket flags");
            close(sock);
            return -1;
        }
        flags |= O_NONBLOCK;
        fcntl(sock, F_SETFL, flags);
        pnt_debug("open_raw_sock: O_NONBLOCK set");
    }

    if (reuse)
    {
        int s = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &s, sizeof(s)) < 0)
        {
            perror("Cannot set SO_REUSEADDR on socket");
            close(sock);
            return -1;
        }
        pnt_debug("open_raw_sock: SO_REUSEADDR set");
    }

    if (bind_device)
    {
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ - 1) < 0)
        {
            perror("Cannot bind to interface");
            close(sock);
            return -1;
        }
        pnt_debug("open_raw_sock: SO_BINDTODEVICE set");
    }

    return sock;
}

int pnt_dcp_create_flashled_request(char *buf, uint8_t *if_src, uint8_t *if_dst)
{
    int send_len = 0;

    /* Construct ehternet header. */
    struct ether_header *eh;
    eh = (struct ether_header *)buf;
    memcpy(eh->ether_shost, if_src, ETH_ALEN);
    memcpy(eh->ether_dhost, if_dst, ETH_ALEN);
    eh->ether_type = htons(ETH_P_PROFINET);

    send_len += sizeof(*eh);

    /* Set PN FrameID to DCP - identify multicast*/
    struct pn_header *pn_hdr;
    pn_hdr = (struct pn_header *)(buf + send_len);
    pn_hdr->h_frame_id = htons(PN_FRAME_ID_RTA_DCP_GETSET);

    send_len += sizeof(*pn_hdr);

    /* Create PN-DCP header */
    struct pn_dcp_header *pn_dcp;
    pn_dcp = (struct pn_dcp_header *)(buf + send_len);
    pn_dcp->h_service_id = PN_DCP_SERVICE_ID_SET;
    pn_dcp->h_service_type = PN_DCP_SERVICE_TYPE_REQUEST;
    pn_dcp->h_xid = htonl(PNT_FLASHLED_XID);
    pn_dcp->h_response_delay = htons(0);
    //pn_dcp->h_dcp_data_length = htons(4);

    send_len += sizeof(*pn_dcp);

    struct pn_dcp_block_control_signal *pn_dcp_block;
    pn_dcp_block = (struct pn_dcp_block_control_signal *)(buf + send_len);
    pn_dcp_block->hdr.h_option = PN_DCP_BLOCK_OPTION_CONTROL;
    pn_dcp_block->hdr.h_suboption = PN_DCP_BLOCK_SUBOPTION_CONTROL_SIGNAL;
    pn_dcp_block->hdr.h_block_length = htons(4);
    pn_dcp_block->block_qualifier = 0;
    pn_dcp_block->signal_value = htons(0x0100); //Flash once

    //set the size of the block on the header
    pn_dcp->h_dcp_data_length = htons(sizeof(*pn_dcp_block));

    send_len += sizeof(*pn_dcp_block);

    return send_len;
}

int pnt_dcp_create_ident_request(char *buf, uint8_t *if_addr)
{
    int send_len = 0;

    /* Construct ehternet header. */
    struct ether_header *eh;
    eh = (struct ether_header *)buf;
    memcpy(eh->ether_shost, if_addr, ETH_ALEN);
    memcpy(eh->ether_dhost, addr_broadcast_pn, ETH_ALEN);
    eh->ether_type = htons(ETH_P_PROFINET);

    send_len += sizeof(*eh);

    /* Set PN FrameID to DCP - identify multicast*/
    struct pn_header *pn_hdr;
    pn_hdr = (struct pn_header *)(buf + send_len);
    pn_hdr->h_frame_id = htons(PN_FRAME_ID_RTA_DCP_REQUEST);

    send_len += sizeof(*pn_hdr);

    /* Create PN-DCP header */
    struct pn_dcp_header *pn_dcp;
    pn_dcp = (struct pn_dcp_header *)(buf + send_len);
    pn_dcp->h_service_id = PN_DCP_SERVICE_ID_IDENTIFY;
    pn_dcp->h_service_type = PN_DCP_SERVICE_TYPE_REQUEST;
    pn_dcp->h_xid = htonl(PNT_DISCOVERY_XID);
    pn_dcp->h_response_delay = htons(128);
    //pn_dcp->h_dcp_data_length = htons(4);

    send_len += sizeof(*pn_dcp);

    struct pn_dcp_block_header *pn_dcp_block;
    pn_dcp_block = (struct pn_dcp_block_header *)(buf + send_len);
    pn_dcp_block->h_option = PN_DCP_BLOCK_OPTION_ALL_SELECTOR;
    pn_dcp_block->h_suboption = PN_DCP_BLOCK_SUBOPTION_ALL_SELECTOR;
    pn_dcp_block->h_block_length = 0;

    //set the size of the block on the header
    pn_dcp->h_dcp_data_length = htons(sizeof(*pn_dcp_block));

    send_len += sizeof(*pn_dcp_block);

    return send_len;
}

#define _CHECK_LENGTH(er) \
    if ((size - ptr) < 0) \
    {                     \
        pnt_debug(er);    \
        return NULL;      \
    }

struct pn_dcp_header *pnt_get_dcp_header(char *buf, ssize_t size, uint8_t *if_addr, uint16_t frameid)
{
    pnt_debug("pnt_get_dcp_header len %lu", size);

    int ptr = 0;
    struct ether_header *eh;
    struct pn_header *pn_hdr;
    struct pn_dcp_header *pn_dcp_hdr;

    eh = (struct ether_header *)buf;
    ptr += sizeof(*eh);
    _CHECK_LENGTH("E: Ether header length");

    /* Receive only destination address is broadcast or me. */
    if (if_addr != NULL &&
        memcmp(eh->ether_dhost, if_addr, ETH_ALEN) != 0 &&
        memcmp(eh->ether_dhost, addr_broadcast, ETH_ALEN) != 0)
    {
        pnt_debug("E: ethernet address mismatch");
        return NULL;
    }

    unsigned int ethertype = ntohs(eh->ether_type);
    pnt_debug("pnt_get_dcp_header type %04x", ethertype);
    if (ethertype == ETH_P_8021Q)
    {
        pnt_debug("pnt_get_dcp_header type vlan");
        struct vlan_hdr *vlan = (struct vlan_hdr *)(buf + ptr);
        ptr += sizeof(*vlan);
        _CHECK_LENGTH("E: VLAN header length");

        if (ntohs(vlan->h_vlan_encapsulated_proto) != ETH_P_PROFINET)
        {
            pnt_debug("E: vlan proto not PROFINET");
            return NULL;
        }
    }
    else if (ethertype != ETH_P_PROFINET)
    {
        pnt_debug("E: eth proto not PROFINET");
        return NULL;
    }

    pn_hdr = (struct pn_header *)(buf + ptr);
    ptr += sizeof(*pn_hdr);
    _CHECK_LENGTH("E: PN header length");

    if (frameid > 0 && ntohs(pn_hdr->h_frame_id) != frameid)
    {
        pnt_debug("E: PN frameid [%04x] not %04x", ntohs(pn_hdr->h_frame_id), frameid);
        return NULL;
    }

    pn_dcp_hdr = (struct pn_dcp_header *)(buf + ptr);
    ptr += sizeof(*pn_dcp_hdr);
    _CHECK_LENGTH("E: PN DCP header length");

    int dcpdatalength = ntohs(pn_dcp_hdr->h_dcp_data_length);
    if (dcpdatalength > (size - ptr))
    {
        pnt_debug("E: PN DCP data-length is [%lu], but only [%lu] bytes left", dcpdatalength, (size - ptr));
        return NULL;
    }

    return pn_dcp_hdr;
}

void pnt_parse_dcp_response_blocks(struct pn_dcp_header *pn_dcp_hdr, struct pn_dcp_identify_response_data *pn_dcp_data)
{
    int dcpdatalen = ntohs(pn_dcp_hdr->h_dcp_data_length);
    int consumed = 0;
    char *ptr = (char *)pn_dcp_hdr;
    ptr += sizeof(*pn_dcp_hdr);

    pnt_debug("pnt_parse_dcp_response_blocks dcp_hdr_len %lu", dcpdatalen);

    while ((dcpdatalen - consumed) > 4) //4: sizeof struct pn_dcp_block_header
    {
        struct pn_dcp_block_header *block_hdr = (struct pn_dcp_block_header *)(ptr + consumed);
        unsigned int blocklen = ntohs(block_hdr->h_block_length);
        pnt_debug("pnt_parse_dcp_response_blocks loop consumed:%lu blocklen:%lu", consumed, blocklen);

        struct pn_dcp_block_dev_props_id *dev_props_id;
        struct pn_dcp_block_dev_props_role *dev_props_role;
        struct pn_dcp_block_addr_ip *addr_ip;

        switch (block_hdr->h_option)
        {
        case PN_DCP_BLOCK_OPTION_DEV_PROPS:

            if (blocklen > 63 || blocklen < 2)
                break; //prevents under/overflowing our char buffers

            switch (block_hdr->h_suboption)
            {
            case PN_DCP_BLOCK_SUBOPTION_DEV_PROPS_CUSTOM:
                memcpy(pn_dcp_data->device_vendorvalue, (ptr + consumed) + 6, blocklen - 2);
                break;
            case PN_DCP_BLOCK_SUBOPTION_DEV_PROPS_NAME:
                memcpy(pn_dcp_data->device_stationname, (ptr + consumed) + 6, blocklen - 2);
                break;
            case PN_DCP_BLOCK_SUBOPTION_DEV_PROPS_ID:
                dev_props_id = (struct pn_dcp_block_dev_props_id *)block_hdr;
                pn_dcp_data->device_id_vendor = ntohs(dev_props_id->id_vendor);
                pn_dcp_data->device_id_device = ntohs(dev_props_id->id_device);
                break;
            case PN_DCP_BLOCK_SUBOPTION_DEV_PROPS_ROLE:
                dev_props_role = (struct pn_dcp_block_dev_props_role *)block_hdr;
                pn_dcp_data->device_role = dev_props_role->dev_role;
                break;
            }
            break;

        case PN_DCP_BLOCK_OPTION_ADDR:
            switch (block_hdr->h_suboption)
            {
            case PN_DCP_BLOCK_SUBOPTION_ADDR_IP:
                addr_ip = (struct pn_dcp_block_addr_ip *)block_hdr;
                pn_dcp_data->device_ip_info = ntohs(addr_ip->h_blockinfo);
                memcpy(pn_dcp_data->device_ip_addr, addr_ip->addr, 4);
                memcpy(pn_dcp_data->device_ip_mask, addr_ip->mask, 4);
                memcpy(pn_dcp_data->device_ip_gateway, addr_ip->gateway, 4);
                break;
            }
            break;
        }

        consumed += blocklen + 4;
        consumed += (blocklen % 2); //word alignment
    }
}