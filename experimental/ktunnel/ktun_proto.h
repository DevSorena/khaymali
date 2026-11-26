#ifndef KHAYMALI_KTUN_PROTO_H
#define KHAYMALI_KTUN_PROTO_H

#include <linux/types.h>

#define KTUN_MAGIC 0x4B543037U /* "KT07" */
#define KTUN_MAX_PAYLOAD 14336U
#define KTUN_TAG_LEN 16U

struct ktun_hdr {
    __be32 magic;
    __be32 stream_id;
    __be64 seq;
    __be16 payload_len;
    __u8   flags;
    __u8   reserved;
    __u8   auth_tag[KTUN_TAG_LEN];
} __attribute__((packed));

#endif /* KHAYMALI_KTUN_PROTO_H */
