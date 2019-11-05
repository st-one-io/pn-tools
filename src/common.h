/*
  Copyright: (c) 2019, Guilherme Francescon Cittolin <gfcittolin@gmail.com>
  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

#ifndef __PNT_COMMON__
#define __PNT_COMMON__

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "version.h"

#define BUF_SIZE (ETH_FRAME_LEN)

#define PNT_DISCOVERY_XID 0x42424242
#define PNT_FLASHLED_XID  0x24242424

static char addr_broadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static char addr_broadcast_pn[ETH_ALEN] = {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00};

#define PNT_VERBOSE_PRINT 1
#define PNT_VERBOSE_DEBUG 2

// ------------------------------------------

#define ETH_P_PROFINET 0x8892

// --- VLAN ---

struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

// --- PN ---

struct pn_header
{
    __be16 h_frame_id;
} __attribute__((packed));

// from Wireshark packet-pn-rt.c                     //pszProtShort; pszProtAddInfo; pszProtSummary; bCyclic; pszProtComment;
#define PN_FRAME_CLASS_001F_RT_RESERVED_1 0x001F     //"PN-RT  ";"reserved,     ";"Real-Time            ";FALSE;"0x0000-0x001F: Reserved ID";
#define PN_FRAME_CLASS_0021_PTCP_FOLLOW 0x0021       //"PN-PTCP";"Synchr.,      ";"Real-Time            ";FALSE;"0x0020-0x0021: Real-Time: Sync (with follow up)";
#define PN_FRAME_CLASS_007F_RT_RESERVED_2 0x007F     //"PN-RT  ";"reserved,     ";"Real-Time            ";FALSE;"0x0022-0x007F: Reserved ID";
#define PN_FRAME_CLASS_0081_PTCP_NOFOLLOW 0x0081     //"PN-PTCP";"Synchr.,      ";"Isochronous-Real-Time";FALSE;"0x0080-0x0081: Real-Time: Sync (without follow up)";
#define PN_FRAME_CLASS_00FF_RT_RESERVED_3 0x00FF     //"PN-RT  ";"reserved,     ";"Real-Time            ";FALSE;"0x0082-0x00FF: Reserved ID";
#define PN_FRAME_CLASS_06FF_RTC3_NOREDUNDANT 0x06FF  //"PN-RTC3";"RTC3,         ";"Isochronous-Real-Time";TRUE ;"0x0100-0x06FF: RED: Real-Time(class=3): non redundant, normal or DFP";
#define PN_FRAME_CLASS_0FFF_RTC3_REDUNDANT 0x0FFF    //"PN-RTC3";"RTC3,         ";"Isochronous-Real-Time";TRUE ;"0x0700-0x0FFF: RED: Real-Time(class=3): redundant, normal or DFP";
#define PN_FRAME_CLASS_7FFF_RT_RESERVED_4 0x7FFF     //"PN-RT  ";"reserved,     ";"Real-Time            ";FALSE;"0x1000-0x7FFF: Reserved ID";
#define PN_FRAME_CLASS_BBFF_RTC1_UNICAST 0xBBFF      //"PN-RTC1";"RTC1,         ";"cyclic Real-Time     ";TRUE ;"0x8000-0xBBFF: Real-Time(class=1 unicast): non redundant, normal";
#define PN_FRAME_CLASS_BFFF_RTC1_MULTICAST 0xBFFF    //"PN-RTC1";"RTC1,         ";"cyclic Real-Time     ";TRUE ;"0xBC00-0xBFFF: Real-Time(class=1 multicast): non redundant, normal";
#define PN_FRAME_CLASS_F7FF_RT_RTC1_LEG_UNI 0xF7FF   //"PN-RT  ";"RTC1(legacy), ";"cyclic Real-Time     ";TRUE ;"0xC000-0xF7FF: Real-Time(class=1 unicast): Cyclic";
#define PN_FRAME_CLASS_FBFF_RT_RTC1_LEG_MULTI 0xFBFF //"PN-RT  ";"RTC1(legacy), ";"cyclic Real-Time     ";TRUE ;"0xF800-0xFBFF: Real-Time(class=1 multicast): Cyclic";
#define PN_FRAME_CLASS_FDFF_RTA_RESERVED_1 0xFDFF    //"PN-RTA ";"Reserved,     ";"acyclic Real-Time    ";FALSE;"0xFC00-0xFDFF: Reserved";
#define PN_FRAME_CLASS_FEFF_RTA_RESERVED_2 0xFEFF    //"PN-RTA ";"Reserved,     ";"acyclic Real-Time    ";FALSE;"0xFE00-0xFEFF: Real-Time: Reserved";
#define PN_FRAME_CLASS_FF01_PTCP_ANNOUNCE 0xFF01     //"PN-PTCP";"RTA Sync,     ";"acyclic Real-Time    ";FALSE;"0xFF00-0xFF01: PTCP Announce";
#define PN_FRAME_CLASS_FF1F_PTCP_RESERVED_1 0xFF1F   //"PN-PTCP";"RTA Sync,     ";"acyclic Real-Time    ";FALSE;"0xFF02-0xFF1F: Reserved";
#define PN_FRAME_CLASS_FF21_PTCP_FOLLOWUP 0xFF21     //"PN-PTCP";"Follow Up,    ";"acyclic Real-Time    ";FALSE;"0xFF20-0xFF21: PTCP Follow Up";
#define PN_FRAME_CLASS_FF22_PTCP_RESERVER 0xFF22     //"PN-PTCP";"Follow Up,    ";"acyclic Real-Time    ";FALSE;"0xFF22-0xFF3F: Reserved";
#define PN_FRAME_CLASS_FF43_PTCP_DELAY 0xFF43        //"PN-PTCP";"Delay,        ";"acyclic Real-Time    ";FALSE;"0xFF40-0xFF43: Acyclic Real-Time: Delay";
#define PN_FRAME_CLASS_FF7F_RT_RESERVED_5 0xFF7F     //"PN-RT  ";"Reserved,     ";"Real-Time            ";FALSE;"0xFF44-0xFF7F: reserved ID";
#define PN_FRAME_CLASS_FF8F_RT_FRAGMENTATION 0xFF8F  //"PN-RT  ";"              ";"Fragmentation        ";FALSE;"0xFF80-0xFF8F: Fragmentation";
#define PN_FRAME_CLASS_FFFF_RT_RESERVED_6 0xFFFF     //"PN-RT  ";"Reserved,     ";"Real-Time            ";FALSE;"0xFF90-0xFFFF: reserved ID";

#define PN_FRAME_ID_RTA_ALARM_HI 0xFC01     //"PN-RTA";"Alarm High, ";"acyclic Real-Time";"Real-Time: Acyclic PN-IO Alarm high priority";
#define PN_FRAME_ID_RTA_ALARM_LO 0xFE01     //"PN-RTA";"Alarm Low,  ";"acyclic Real-Time";"Real-Time: Acyclic PN-IO Alarm low priority";
#define PN_FRAME_ID_RTA_DCP_HELLO 0xFEfC    //"PN-RTA";"            ";"acyclic Real-Time";"Real-Time: DCP hello";
#define PN_FRAME_ID_RTA_DCP_GETSET 0xFEFD   //"PN-RTA";"            ";"acyclic Real-Time";"Real-Time: DCP get/set";
#define PN_FRAME_ID_RTA_DCP_REQUEST 0xFEFE  //"PN-RTA";"            ";"acyclic Real-Time";"Real-Time: DCP identify multicast request";
#define PN_FRAME_ID_RTA_DCP_RESPONSE 0xFEFF //"PN-RTA";"            ";"acyclic Real-Time";"Real-Time: DCP identify response";

struct pn_footer
{
    __be16 f_cycle_counter;
    __u8 f_data_status;
    __u8 f_transfer_status;
} __attribute__((packed));

// --- PN_DCP ---

#define PN_DCP_SERVICE_ID_GET 3
#define PN_DCP_SERVICE_ID_SET 4
#define PN_DCP_SERVICE_ID_IDENTIFY 5
#define PN_DCP_SERVICE_ID_HELLP 5

#define PN_DCP_SERVICE_TYPE_REQUEST 0
#define PN_DCP_SERVICE_TYPE_RESPONSE_SUCCESS 1
#define PN_DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED 5

struct pn_dcp_header
{
    __u8 h_service_id;
    __u8 h_service_type;
    __be32 h_xid;
    __be16 h_response_delay;
    __be16 h_dcp_data_length;
} __attribute__((packed));

#define PN_DCP_BLOCK_OPTION_ADDR 1
#define PN_DCP_BLOCK_OPTION_DEV_PROPS 2
#define PN_DCP_BLOCK_OPTION_DHCP 3
#define PN_DCP_BLOCK_OPTION_LLDP 4
#define PN_DCP_BLOCK_OPTION_CONTROL 5
#define PN_DCP_BLOCK_OPTION_ALL_SELECTOR 255

#define PN_DCP_BLOCK_SUBOPTION_ADDR_MAC 1
#define PN_DCP_BLOCK_SUBOPTION_ADDR_IP 2

#define PN_DCP_BLOCK_SUBOPTION_DEV_PROPS_CUSTOM 1
#define PN_DCP_BLOCK_SUBOPTION_DEV_PROPS_NAME 2
#define PN_DCP_BLOCK_SUBOPTION_DEV_PROPS_ID 3
#define PN_DCP_BLOCK_SUBOPTION_DEV_PROPS_ROLE 4
#define PN_DCP_BLOCK_SUBOPTION_DEV_PROPS_OPTS 5
#define PN_DCP_BLOCK_SUBOPTION_DEV_PROPS_ALIAS 6
#define PN_DCP_BLOCK_SUBOPTION_DEV_PROPS_INSTANCE 7

#define PN_DCP_BLOCK_SUBOPTION_CONTROL_START_TRANS 0x01
#define PN_DCP_BLOCK_SUBOPTION_CONTROL_END_TRANS 0x02
#define PN_DCP_BLOCK_SUBOPTION_CONTROL_SIGNAL 0x03
#define PN_DCP_BLOCK_SUBOPTION_CONTROL_RESPONSE 0x04
#define PN_DCP_BLOCK_SUBOPTION_CONTROL_FACT_RESET 0x05

#define PN_DCP_BLOCK_SUBOPTION_ALL_SELECTOR 255

struct pn_dcp_block_header
{
    __u8 h_option;
    __u8 h_suboption;
    __be16 h_block_length;
} __attribute__((packed));

struct pn_dcp_block_dev_props_custom
{
    struct pn_dcp_block_header hdr;
    __be16 h_blockinfo;
    //char* data;
} __attribute__((packed));

struct pn_dcp_block_dev_props_id
{
    struct pn_dcp_block_header hdr;
    __be16 h_blockinfo;
    __be16 id_vendor;
    __be16 id_device;
} __attribute__((packed));

struct pn_dcp_block_dev_props_role
{
    struct pn_dcp_block_header hdr;
    __be16 h_blockinfo;
    __u8 dev_role;
    __u8 reserved;
} __attribute__((packed));

struct pn_dcp_block_addr_ip
{
    struct pn_dcp_block_header hdr;
    __be16 h_blockinfo;
    __u8 addr[4];
    __u8 mask[4];
    __u8 gateway[4];
} __attribute__((packed));

struct pn_dcp_block_control_signal
{
    struct pn_dcp_block_header hdr;
    __be16 block_qualifier;
    __be16 signal_value;
} __attribute__((packed));

struct pn_dcp_block_control_response
{
    struct pn_dcp_block_header hdr;
    __u8 response;
    __u8 response_suboption;
    __u8 error;
} __attribute__((packed));

struct pn_dcp_identify_response_data
{
    char device_vendorvalue[64];
    char device_stationname[64];
    uint16_t device_id_vendor;
    uint16_t device_id_device;
    uint8_t device_role;
    uint16_t device_ip_info;
    uint8_t device_ip_addr[4];
    uint8_t device_ip_mask[4];
    uint8_t device_ip_gateway[4];
};

// -------------------------------------------

void pnt_set_verbose_level(int lvl);
int pnt_get_verbose_level();
void pnt_debug(const char *format, ...);
void pnt_print(const char *format, ...);
void dump_buffer(char *buf, unsigned int length);

int open_raw_sock(char *if_name, uint8_t *if_addr, int *if_index,
                  int do_promiscuous, int non_block, int reuse, int bind_device);
int pnt_dcp_create_flashled_request(char *buf, uint8_t *if_src, uint8_t *if_dst);
int pnt_dcp_create_ident_request(char *buf, uint8_t *if_addr);
struct pn_dcp_header *pnt_get_dcp_header(char *buf, ssize_t size, uint8_t *if_addr, uint16_t frameid);
void pnt_parse_dcp_response_blocks(struct pn_dcp_header *pn_dcp_hdr, struct pn_dcp_identify_response_data *pn_dcp_data);

#endif