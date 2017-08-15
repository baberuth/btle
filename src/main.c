#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#define BTNAME "hci0"
#define BTPROTO_HCI 1


#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif


#define FLAGS_AD_TYPE 0x01
#define FLAGS_LIMITED_MODE_BIT 0x01
#define FLAGS_GENERAL_MODE_BIT 0x02

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_DEVICE_ID               0x10  /* device ID */

#define HCI_MAX_ACL_SIZE        (1492 + 4)
#define HCI_MAX_SCO_SIZE        255
#define HCI_MAX_EVENT_SIZE      260
#define HCI_MAX_FRAME_SIZE      (HCI_MAX_ACL_SIZE + 4)
#define SOL_HCI         0
#define HCI_FILTER	2

#define EVT_CMD_STATUS                  0x0F
typedef struct {
        uint8_t         status;
        uint8_t         ncmd;
        uint16_t        opcode;
} __attribute__ ((packed)) evt_cmd_status;
#define EVT_CMD_STATUS_SIZE 4

#define HCI_MAX_NAME_LENGTH             248

#define EVT_CMD_COMPLETE                0x0E
typedef struct {
        uint8_t         ncmd;
        uint16_t        opcode;
} __attribute__ ((packed)) evt_cmd_complete; 
#define EVT_CMD_COMPLETE_SIZE 3

#define EVT_LE_META_EVENT       0x3E
typedef struct {
        uint8_t         subevent;
        uint8_t         data[0];
} __attribute__ ((packed)) evt_le_meta_event;
#define EVT_LE_META_EVENT_SIZE 1



struct hci_filter {
        uint32_t type_mask;
        uint32_t event_mask[2];
        uint16_t opcode;
};  


#define HCI_FLT_TYPE_BITS       31
#define HCI_FLT_EVENT_BITS      63
#define HCI_FLT_OGF_BITS        63
#define HCI_FLT_OCF_BITS        127

typedef struct {
        uint8_t b[6];
} __attribute__((packed)) bdaddr_t;


static inline int bacmp(const bdaddr_t *ba1, const bdaddr_t *ba2)
{
        return memcmp(ba1, ba2, sizeof(bdaddr_t));
}
static inline void bacpy(bdaddr_t *dst, const bdaddr_t *src)
{
        memcpy(dst, src, sizeof(bdaddr_t));
}

#define OCF_REMOTE_NAME_REQ             0x0019
typedef struct {
        bdaddr_t        bdaddr;
        uint8_t         pscan_rep_mode;
        uint8_t         pscan_mode;
        uint16_t        clock_offset;
} __attribute__ ((packed)) remote_name_req_cp;
#define REMOTE_NAME_REQ_CP_SIZE 10

#define EVT_REMOTE_NAME_REQ_COMPLETE    0x07
typedef struct {
        uint8_t         status;
        bdaddr_t        bdaddr;
        uint8_t         name[HCI_MAX_NAME_LENGTH];
} __attribute__ ((packed)) evt_remote_name_req_complete;
#define EVT_REMOTE_NAME_REQ_COMPLETE_SIZE 255


typedef struct {
        uint8_t         evt;
        uint8_t         plen;
} __attribute__ ((packed))      hci_event_hdr;
#define HCI_EVENT_HDR_SIZE      2

/* LE commands */
#define OGF_LE_CTL              0x08
        
#define OCF_LE_SET_EVENT_MASK                   0x0001
typedef struct {
        uint8_t         mask[8];
} __attribute__ ((packed)) le_set_event_mask_cp;
#define LE_SET_EVENT_MASK_CP_SIZE 8
        
#define OCF_LE_READ_BUFFER_SIZE                 0x0002
typedef struct {
        uint8_t         status;
        uint16_t        pkt_len;
        uint8_t         max_pkt;
} __attribute__ ((packed)) le_read_buffer_size_rp;
#define LE_READ_BUFFER_SIZE_RP_SIZE 4
        
#define OCF_LE_READ_LOCAL_SUPPORTED_FEATURES    0x0003
typedef struct {
        uint8_t         status;
        uint8_t         features[8];
} __attribute__ ((packed)) le_read_local_supported_features_rp;
#define LE_READ_LOCAL_SUPPORTED_FEATURES_RP_SIZE 9

#define OCF_LE_SET_RANDOM_ADDRESS               0x0005
typedef struct {
        bdaddr_t        bdaddr;
} __attribute__ ((packed)) le_set_random_address_cp;
#define LE_SET_RANDOM_ADDRESS_CP_SIZE 6

#define OCF_LE_SET_ADVERTISING_PARAMETERS       0x0006
typedef struct {
        uint16_t        min_interval;
        uint16_t        max_interval;
        uint8_t         advtype;
        uint8_t         own_bdaddr_type;
        uint8_t         direct_bdaddr_type;
        bdaddr_t        direct_bdaddr;
        uint8_t         chan_map;
        uint8_t         filter;
} __attribute__ ((packed)) le_set_advertising_parameters_cp;
#define LE_SET_ADVERTISING_PARAMETERS_CP_SIZE 15

#define OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER        0x0007
typedef struct {
        uint8_t         status;
        int8_t          level;
} __attribute__ ((packed)) le_read_advertising_channel_tx_power_rp;
#define LE_READ_ADVERTISING_CHANNEL_TX_POWER_RP_SIZE 2

#define OCF_LE_SET_ADVERTISING_DATA             0x0008
typedef struct {
        uint8_t         length;
        uint8_t         data[31];
} __attribute__ ((packed)) le_set_advertising_data_cp;
#define LE_SET_ADVERTISING_DATA_CP_SIZE 32

#define OCF_LE_SET_SCAN_RESPONSE_DATA           0x0009
typedef struct {
        uint8_t         length;
        uint8_t         data[31];
} __attribute__ ((packed)) le_set_scan_response_data_cp;
#define LE_SET_SCAN_RESPONSE_DATA_CP_SIZE 32

#define OCF_LE_SET_ADVERTISE_ENABLE             0x000A
typedef struct {
        uint8_t         enable;
} __attribute__ ((packed)) le_set_advertise_enable_cp;
#define LE_SET_ADVERTISE_ENABLE_CP_SIZE 1

#define OCF_LE_SET_SCAN_PARAMETERS              0x000B
typedef struct {
        uint8_t         type;
        uint16_t        interval;
        uint16_t        window;
        uint8_t         own_bdaddr_type;
        uint8_t         filter;
} __attribute__ ((packed)) le_set_scan_parameters_cp;
#define LE_SET_SCAN_PARAMETERS_CP_SIZE 7

#define OCF_LE_SET_SCAN_ENABLE                  0x000C
typedef struct {
        uint8_t         enable;
        uint8_t         filter_dup;
} __attribute__ ((packed)) le_set_scan_enable_cp;
#define LE_SET_SCAN_ENABLE_CP_SIZE 2

struct sockaddr_hci {
        sa_family_t     hci_family;
        unsigned short  hci_dev;
        unsigned short  hci_channel;
};

struct hci_request {
        uint16_t ogf;
        uint16_t ocf;
        int      event;
        void     *cparam;
        int      clen;
        void     *rparam;
        int      rlen;
};

typedef struct {
        uint16_t        opcode;         /* OCF & OGF */
        uint8_t         plen;
} __attribute__ ((packed))      hci_command_hdr;
#define HCI_COMMAND_HDR_SIZE    3

#define HCI_COMMAND_PKT         0x01
#define HCI_ACLDATA_PKT         0x02
#define HCI_SCODATA_PKT         0x03
#define HCI_EVENT_PKT           0x04
#define HCI_VENDOR_PKT          0xff

#define htobs(d)  (d)
#define htobl(d)  (d)
#define htobll(d) (d)
#define btohs(d)  (d)
#define btohl(d)  (d)
#define btohll(d) (d)

#define cmd_opcode_pack(ogf, ocf)       (uint16_t)((ocf & 0x03ff)|(ogf << 10))
#define cmd_opcode_ogf(op)              (op >> 10)
#define cmd_opcode_ocf(op)              (op & 0x03ff)
        
/* ACL handle and flags pack/unpack */
#define acl_handle_pack(h, f)   (uint16_t)((h & 0x0fff)|(f << 12))
#define acl_handle(h)           (h & 0x0fff)
#define acl_flags(h)            (h >> 12)

static inline void hci_set_bit(int nr, void *addr)
{
        *((uint32_t *) addr + (nr >> 5)) |= (1 << (nr & 31));
}

static inline void hci_clear_bit(int nr, void *addr)
{
        *((uint32_t *) addr + (nr >> 5)) &= ~(1 << (nr & 31));
}


static inline void hci_filter_clear(struct hci_filter *f)
{       
        memset(f, 0, sizeof(*f));
}               
static inline void hci_filter_set_ptype(int t, struct hci_filter *f)
{               
        hci_set_bit((t == HCI_VENDOR_PKT) ? 0 : (t & HCI_FLT_TYPE_BITS), &f->type_mask);
}               
static inline void hci_filter_clear_ptype(int t, struct hci_filter *f)
{               
        hci_clear_bit((t == HCI_VENDOR_PKT) ? 0 : (t & HCI_FLT_TYPE_BITS), &f->type_mask);
}                       
static inline int hci_filter_test_ptype(int t, struct hci_filter *f)
{                       
        return hci_test_bit((t == HCI_VENDOR_PKT) ? 0 : (t & HCI_FLT_TYPE_BITS), &f->type_mask);
}                               
static inline void hci_filter_all_ptypes(struct hci_filter *f)
{                               
        memset((void *) &f->type_mask, 0xff, sizeof(f->type_mask));
}
static inline void hci_filter_set_event(int e, struct hci_filter *f)
{                               
        hci_set_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline void hci_filter_clear_event(int e, struct hci_filter *f)
{
        hci_clear_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline int hci_filter_test_event(int e, struct hci_filter *f)
{
        return hci_test_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline void hci_filter_all_events(struct hci_filter *f)
{
        memset((void *) f->event_mask, 0xff, sizeof(f->event_mask));
}
static inline void hci_filter_set_opcode(int opcode, struct hci_filter *f)
{
        f->opcode = opcode;
}
static inline void hci_filter_clear_opcode(struct hci_filter *f)
{
        f->opcode = 0;
}
static inline int hci_filter_test_opcode(int opcode, struct hci_filter *f)
{
        return (f->opcode == opcode);
}

int hci_send_cmd(int dd, uint16_t ogf, uint16_t ocf, uint8_t plen, void *param)
{
        uint8_t type = HCI_COMMAND_PKT;
        hci_command_hdr hc;
        struct iovec iv[3];
        int ivn;

        hc.opcode = htobs(cmd_opcode_pack(ogf, ocf));
        hc.plen= plen;

        iv[0].iov_base = &type;
        iv[0].iov_len  = 1;
        iv[1].iov_base = &hc;
        iv[1].iov_len  = HCI_COMMAND_HDR_SIZE;
        ivn = 2;

        if (plen) {
                iv[2].iov_base = param;
                iv[2].iov_len  = plen;
                ivn = 3;
        }

        while (writev(dd, iv, ivn) < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        continue;
		printf("write\n");
                return -1;
        }
        return 0;
}

int hci_send_req(int dd, struct hci_request *r, int to)
{
        unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
        uint16_t opcode = htobs(cmd_opcode_pack(r->ogf, r->ocf));
        struct hci_filter nf, of;
        socklen_t olen;
        hci_event_hdr *hdr;
        int err, try;

        olen = sizeof(of);
        if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0)
                return -1;

        hci_filter_clear(&nf);
        hci_filter_set_ptype(HCI_EVENT_PKT,  &nf);
        hci_filter_set_event(EVT_CMD_STATUS, &nf);
        hci_filter_set_event(EVT_CMD_COMPLETE, &nf);
        hci_filter_set_event(EVT_LE_META_EVENT, &nf);
        hci_filter_set_event(r->event, &nf);
        hci_filter_set_opcode(opcode, &nf);
        if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
                return -1;
	printf("ZZ send_cmd\n");
        if (hci_send_cmd(dd, r->ogf, r->ocf, r->clen, r->cparam) < 0)
                goto failed;

	printf("ZZ send_cmd completed\n");
        try = 10;
        while (try--) {
                evt_cmd_complete *cc;
                evt_cmd_status *cs;
                evt_remote_name_req_complete *rn;
                evt_le_meta_event *me;
                remote_name_req_cp *cp;
                int len;

                if (to) {
                        struct pollfd p;
                        int n;

                        p.fd = dd; p.events = POLLIN;
                        while ((n = poll(&p, 1, to)) < 0) {
                                if (errno == EAGAIN || errno == EINTR)
                                        continue;
                                goto failed;
                        }

                        if (!n) {
                                errno = ETIMEDOUT;
                                goto failed;
                        }

                        to -= 10;
                        if (to < 0)
                                to = 0;

                }

                while ((len = read(dd, buf, sizeof(buf))) < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                continue;
                        goto failed;
                }

                hdr = (void *) (buf + 1);
                ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
                len -= (1 + HCI_EVENT_HDR_SIZE);

                switch (hdr->evt) {
                case EVT_CMD_STATUS:
                        cs = (void *) ptr;

                        if (cs->opcode != opcode)
                                continue;

                        if (r->event != EVT_CMD_STATUS) {
                                if (cs->status) {
                                        errno = EIO;
                                        goto failed;
                                }
                                break;
                        }

                        r->rlen = MIN(len, r->rlen);
                        memcpy(r->rparam, ptr, r->rlen);
                        goto done;

                case EVT_CMD_COMPLETE:
                        cc = (void *) ptr;
                        if (cc->opcode != opcode)
                                continue;

                        ptr += EVT_CMD_COMPLETE_SIZE;
                        len -= EVT_CMD_COMPLETE_SIZE;

                        r->rlen = MIN(len, r->rlen);
                        memcpy(r->rparam, ptr, r->rlen);
                        goto done;

                case EVT_REMOTE_NAME_REQ_COMPLETE:
                        if (hdr->evt != r->event)
                                break;

                        rn = (void *) ptr;
                        cp = r->cparam;

                        if (bacmp(&rn->bdaddr, &cp->bdaddr))
                                continue;

                        r->rlen = MIN(len, r->rlen);
                        memcpy(r->rparam, ptr, r->rlen);
                        goto done;

                case EVT_LE_META_EVENT:
                        me = (void *) ptr;

                        if (me->subevent != r->event)
                                continue;

                        len -= 1;
                        r->rlen = MIN(len, r->rlen);
                        memcpy(r->rparam, me->data, r->rlen);
                        goto done;

                default:
                        if (hdr->evt != r->event)
                                break;

                        r->rlen = MIN(len, r->rlen);
                        memcpy(r->rparam, ptr, r->rlen);
                        goto done;
                }
        }
        errno = ETIMEDOUT;

failed:
        err = errno;
	printf("ZZ error\n");
        setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
        errno = err;
        return -1;

done:
	printf("ZZ done\n");
        setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
        return 0;
}

int hci_le_set_scan_enable(int dd, uint8_t enable, uint8_t filter_dup, int to)
{
        struct hci_request rq;
        le_set_scan_enable_cp scan_cp;
        uint8_t status;

        memset(&scan_cp, 0, sizeof(scan_cp));
        scan_cp.enable = enable;
        scan_cp.filter_dup = filter_dup;

        memset(&rq, 0, sizeof(rq));
        rq.ogf = OGF_LE_CTL;
        rq.ocf = OCF_LE_SET_SCAN_ENABLE;
        rq.cparam = &scan_cp;
        rq.clen = LE_SET_SCAN_ENABLE_CP_SIZE;
        rq.rparam = &status;
        rq.rlen = 1;    

        if (hci_send_req(dd, &rq, to) < 0)
                return -1;

        if (status) {
                errno = EIO;
                return -1;
        }

        return 0;
}

int32_t signal_received = 0;

static void sigint_handler(int sig)
{
        signal_received = sig;
}
#define EVT_LE_ADVERTISING_REPORT       0x02
typedef struct {
        uint8_t         evt_type;
        uint8_t         bdaddr_type;
        bdaddr_t        bdaddr;
        uint8_t         length;
        uint8_t         data[0];
} __attribute__ ((packed)) le_advertising_info;
#define LE_ADVERTISING_INFO_SIZE 9

int ba2str(const bdaddr_t *ba, char *str)
{
        return sprintf(str, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
                ba->b[5], ba->b[4], ba->b[3], ba->b[2], ba->b[1], ba->b[0]);
}
static void eir_parse_name(uint8_t *eir, size_t eir_len,
                                                char *buf, size_t buf_len)
{
        size_t offset;

        offset = 0;
        while (offset < eir_len) {
                uint8_t field_len = eir[0];
                size_t name_len;

                /* Check for the end of EIR */
                if (field_len == 0)
                        break;

                if (offset + field_len > eir_len)
                        goto failed;

                switch (eir[1]) {
                case EIR_NAME_SHORT:
                case EIR_NAME_COMPLETE:
                        name_len = field_len - 1;
                        if (name_len > buf_len)
                                goto failed;

                        memcpy(buf, &eir[2], name_len);
                        return;
                }

                offset += field_len + 1;
                eir += field_len + 1;
        }

failed:
        snprintf(buf, buf_len, "(unknown)");
}

static int read_flags(uint8_t *flags, const uint8_t *data, size_t size)
{
        size_t offset;

        if (!flags || !data)
                return -EINVAL;

        offset = 0;
        while (offset < size) {
                uint8_t len = data[offset];
                uint8_t type;

                /* Check if it is the end of the significant part */
                if (len == 0)
                        break;

                if (len + offset > size)
                        break;

                type = data[offset + 1];

                if (type == FLAGS_AD_TYPE) {
                        *flags = data[offset + 2];
                        return 0;
                }

                offset += 1 + len;
        }

        return -ENOENT;
}

static int check_report_filter(uint8_t procedure, le_advertising_info *info)
{
        uint8_t flags;

        /* If no discovery procedure is set, all reports are treat as valid */
        if (procedure == 0)
                return 1;

        /* Read flags AD type value from the advertising report if it exists */
        if (read_flags(&flags, info->data, info->length))
                return 0;

        switch (procedure) {
        case 'l': /* Limited Discovery Procedure */
                if (flags & FLAGS_LIMITED_MODE_BIT)
                        return 1;
                break;
        case 'g': /* General Discovery Procedure */
                if (flags & (FLAGS_LIMITED_MODE_BIT | FLAGS_GENERAL_MODE_BIT))
                        return 1;
                break;
        default:
                fprintf(stderr, "Unknown discovery procedure\n");
        }

        return 0;
}

static int print_advertising_devices(int dd, uint8_t filter_type)
{
        unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
        struct hci_filter nf, of;
        struct sigaction sa;
        socklen_t olen;
        int len;

        olen = sizeof(of);
        if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
                printf("Could not get socket options\n");
                return -1;
        }

        hci_filter_clear(&nf);
        hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
        hci_filter_set_event(EVT_LE_META_EVENT, &nf);

        if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
                printf("Could not set socket options\n");
                return -1;
        }

        memset(&sa, 0, sizeof(sa));
        sa.sa_flags = SA_NOCLDSTOP;
        sa.sa_handler = sigint_handler;
        sigaction(SIGINT, &sa, NULL);

        while (1) {
                evt_le_meta_event *meta;
                le_advertising_info *info;
                char addr[18];

                while ((len = read(dd, buf, sizeof(buf))) < 0) {
                        if (errno == EINTR && signal_received == SIGINT) {
                                len = 0;
                                goto done;
                        }

                        if (errno == EAGAIN || errno == EINTR)
                                continue;
                        goto done;
                }

                ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
                len -= (1 + HCI_EVENT_HDR_SIZE);

                meta = (void *) ptr;

                if (meta->subevent != 0x02)
                        goto done;

                /* Ignoring multiple reports */
                info = (le_advertising_info *) (meta->data + 1);
                if (check_report_filter(filter_type, info)) {
                        char name[30];

                        memset(name, 0, sizeof(name));

                        ba2str(&info->bdaddr, addr);
                        eir_parse_name(info->data, info->length,
                                                        name, sizeof(name) - 1);

                        printf("%s %s\n", addr, name);
			printf("len %d\n", info->length);
                }
        }

done:
        setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

        if (len < 0)
                return -1;

        return 0;
}



int main(int argc, char * argv[])
{
	int dd, err;
	struct sockaddr_hci a;
	struct hci_request rq;
        le_set_scan_parameters_cp param_cp;
        uint8_t status;


 	dd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
        if (dd < 0)
                return dd;

        /* Bind socket to the HCI device */
        memset(&a, 0, sizeof(a));
        a.hci_family = AF_BLUETOOTH;
        a.hci_dev = 0;
        if (bind(dd, (struct sockaddr *) &a, sizeof(a)) < 0)
		exit(-1);

	memset(&param_cp, 0, sizeof(param_cp));
        param_cp.type = 1;
        param_cp.interval = 0x0010;
        param_cp.window = 0x0010;
        param_cp.own_bdaddr_type = 0;
        param_cp.filter = 0;

        memset(&rq, 0, sizeof(rq));
        rq.ogf = OGF_LE_CTL;
        rq.ocf = OCF_LE_SET_SCAN_PARAMETERS;
        rq.cparam = &param_cp;
        rq.clen = LE_SET_SCAN_PARAMETERS_CP_SIZE;
        rq.rparam = &status;
        rq.rlen = 1;
	printf("ZZ enable 1\n");
	if (hci_send_req(dd, &rq, 10*1000) < 0)
                return -1;

        if (status) {
                errno = EIO;
                return -1;
        }
printf("ZZ enable 2\n");

	   err = hci_le_set_scan_enable(dd, 0x01, 0, 10000);
        if (err < 0) {
                perror("Enable scan failed");
                exit(1);
        }

    	err = print_advertising_devices(dd, 0);
        if (err < 0) {
                perror("Could not receive advertising events");
                exit(1);
        }


	   err = hci_le_set_scan_enable(dd, 0x00, 0, 10000);

	close(dd);
	return 0;
}
