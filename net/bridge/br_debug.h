#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/if_vlan.h>


enum skb_tcp_debug_op {
    SKB_TCP_PRINT_SEQ,
    SKB_TCP_CHECK_FIN,
    SKB_TCP_CHECK_ACK,
    SKB_TCP_CHECK_SYN
};

enum skb_debug_op {
    SKB_METADATA_LAYOUT     = 1 << 0,
    SKB_NONLINEAR           = 1 << 1,
    SKB_DUMP_ALL            = SKB_METADATA_LAYOUT | SKB_NONLINEAR,
};

#ifndef SKB_PAYLOAD_MAX_BYTES
#define SKB_PAYLOAD_MAX_BYTES 256U
#endif

/*** IP Layer DEBUG ***/
bool skb_src_ip_match(struct sk_buff *skb, u32 ip);
bool skb_dst_ip_match(struct sk_buff *skb, u32 ip);

/*** SKB_Level_DEBUG ***/
void skb_metadata_compare(struct sk_buff *first_skb, struct sk_buff* second_skb);
void skb_debug_dump(struct sk_buff *skb, enum skb_debug_op op, const char *msg);

/*** TCP_Layer_DEBUG ***/
bool skb_tcp_debug_handler(struct sk_buff *skb, enum skb_tcp_debug_op op, const char *msg);

