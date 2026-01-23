// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
#include <net/netfilter/nf_queue.h>
#endif
#include <linux/neighbour.h>
#include <net/arp.h>
#include <net/dsa.h>
#include <linux/export.h>
#include <linux/rculist.h>
#include <linux/skbuff.h>
#include <linux/mm.h>
#include "br_private.h"
#include "br_private_tunnel.h"

extern void* cxl_offset_mem_addr;
extern void* cxl_numa_mem_addr;



#define TARGET_IP htonl(0xC0A86402) /* 192.168.100.2 */

/**
 * replace_skb_with_cxl_page - 用 CXL 物理页替换 skb 的非线性数据区
 * @skb: 需要修改的 socket buffer
 * @cxl_pfn: CXL 数据的起始物理页帧号
 * @data_offset: 数据在 CXL 页内的偏移
 * @data_len: 数据长度
 *
 * 注意：调用者需确保 skb 有足够的空间或已被合理初始化
 */
void replace_skb_with_cxl_page(struct sk_buff *skb, int cxl_pfn, 
                               unsigned int data_offset, unsigned int data_len, unsigned int headlen)
{
    struct page *cxl_page;
    skb_frag_t *frag;
    struct skb_shared_info *shinfo = skb_shinfo(skb);
    int i;

    // 1. 获取 CXL 对应的 struct page
	
    cxl_page = pfn_to_page(cxl_pfn);
    if (!cxl_page)
        return;

    // 2. 设置较大的引用计数基数，防止协议栈回收
    // 假设该页面是静态预留的，将其引用计数设为 1024
    // 这样即便经过多次 put_page，计数也不会归零
    // set_page_count(cxl_page, 1024);
	SetPageReserved(cxl_page);

	if( page_count(cxl_page) <= 10)
		get_page(cxl_page);

	pr_info("DEBUG: CXL Page PFN: 0x%lx, RefCount After: %d\n", 
        page_to_pfn(cxl_page), page_count(cxl_page));
    // 3. 释放 skb 现有的所有非线性区 frags（防止内存泄漏）
	frag = &shinfo->frags[0];
	/**** bug ****/
    // if (skb_frag_page(frag))
    //     put_page(skb_frag_page(frag));

	// 4. 替换为 CXL 页面
    // 我们这里假设数据量较小，只需一个页。如果跨页，需要循环填充。
    
    // 手动设置第一个分片
    frag->bv_page = cxl_page;        /* ← 关键点 */
    frag->bv_offset = data_offset;
    frag->bv_len = data_len; 

    // 5. 更新 shinfo 的分片计数
    shinfo->nr_frags = 1;

    // 6. 关键：更新 skb 的长度字段
    // 减去旧的 data_len，加上新的 data_len
    unsigned int old_data_len = skb->data_len;
    skb->data_len = data_len;
    skb->len = skb->data_len + headlen;

    // // 7. 更新 truesize (可选，取决于你是否需要精确计费)
    // // CXL 内存不占用系统内存配额，但为了防止内核报警，可以设置一个合理值
    skb->truesize = skb->truesize - old_data_len + data_len;

    // // // 8. 标记该 skb 的数据已被修改（如果是转发，可能需要重新计算 checksum）
    skb->ip_summed = CHECKSUM_UNNECESSARY; 
	// skb_reset_mac_header(skb);
	skb_set_network_header(skb, 0);
	skb_set_transport_header(skb, 20);
}

void content_test(int pfn){

    if (!pfn_valid(pfn)) {
        pr_err("PFN %lu has no struct page\n", pfn);
        return;
    }
    struct page *page = pfn_to_page(pfn);

    pr_info("page phys addr = 0x%llx\n",
        (unsigned long long)page_to_phys(page));
    void *addr1 = kmap_local_page(page);

    print_hex_dump(KERN_INFO,
                   "page dump: ",
                   DUMP_PREFIX_OFFSET,
                   16, 1,
                   addr1,
                   64,
                   true);

    kunmap_local(addr1);
}

void copy_skb_whole_linear_with_shinfo(struct sk_buff *skb, u32 size, u64 offset)
{

    if (!skb)
        return;
	// pr_info("COPY:data addr:0x%llx\n", skb->data);

    memcpy(skb->data, ((char*)cxl_numa_mem_addr)+offset ,size);
	// pr_info("[replace test]:offset:0x%llx,size:%u ",offset,size);
	
	// 恢复布局的相对位置
	/* 1. 恢复 data 和 tail 的相对位置 */
    /* 这样能保证 data 依然在 78，tail 依然在 130 */
    // skb->data = skb->head + old_data_off;
	skb_reset_tail_pointer(skb);
	
	skb_put(skb, size);
	skb_pull(skb,14);
	// pr_info("0x%llx\n",skb_tail_pointer(skb));

}

void debug_print_skb_layout_in(const struct sk_buff *skb, const char *msg)
{
    if (!skb) {
        pr_info("skb_debug: [%s] skb is NULL\n", msg);
        return;
    }

    pr_info("skb_debug: === [%s] Layout ===\n", msg);

    /* 1. 绝对指针地址 (Pointers) */
    pr_info("  Addresses: head=%px, data=%px, tail=%px, end=%px\n",
            skb->head, skb->data, skb_tail_pointer(skb), skb_end_pointer(skb));

    /* 2. 相对偏移量 (Offsets from head) */
    /* head 永远是 0 */
    pr_info("  Offsets:   head=0, data=%d, tail=%d, end=%d\n",
            (int)(skb->data - skb->head),
            (int)(skb_tail_pointer(skb) - skb->head),
            (int)(skb_end_offset(skb)));

    /* 3. 长度信息 (Lengths) */
    pr_info("  Lengths:   len=%u, data_len=%u, headlen=%u\n",
            skb->len, skb->data_len, skb_headlen(skb));

    /* 4. 剩余空间 (Room) */
    pr_info("  Room:      headroom=%u, tailroom=%u\n",
            skb_headroom(skb), skb_tailroom(skb));

    /* 5. 分片信息 (Non-linear info) */
    if (skb_is_nonlinear(skb)) {
        pr_info("  Non-linear: nr_frags=%u\n", skb_shinfo(skb)->nr_frags);
    } else {
        pr_info("  Non-linear: (Linear Only)\n");
    }

    pr_info("skb_debug: =========================\n");
}

static void ring_init(struct cxl_skb_ring * ring)
{
	ring->head = 0;
	ring->tail = 0;
	ring->init_mark = 1;
	clflush(ring);
}
static u32 get_ring_budget(struct cxl_skb_ring* ring, u32* current_tail)
{
	
	clflush(ring);
	u32 head = ring->head;
	__rmb();
	// pr_info("head:%d tail:%d, current_tail:%d\n", ring->head, ring->tail, *current_tail);
	// no new entry to read
	if(*current_tail == head)
		return 0;
	//update tail value
	ring->tail = *current_tail;
	__wmb();
	if(*current_tail < head)
		return head - (*current_tail);  
	else
		return ring->ring_size - (*current_tail) + head;
}

static void ring_pop(struct cxl_skb_ring* ring, struct cxl_skb_entry* recv_entry, u32* current_tail)
{
	clflush(&ring->buf[*current_tail]);
	struct cxl_skb_entry* entry_in = &ring->buf[*current_tail];
	__rmb();
	// pr_info("[POP]tail:%u,offset:0x%lx,size:%u\n",*current_tail,ring->buf[*current_tail].header.offset, ring->buf[*current_tail].header.size);
	recv_entry->header.offset = entry_in->header.offset;
	recv_entry->header.size = entry_in->header.size;
	recv_entry->payload.pfn = entry_in->payload.pfn;
	recv_entry->payload.size = entry_in->payload.size;

	*current_tail = ((*current_tail)+1)%RING_SIZE;

}

static void skb_configure(struct sk_buff* new_skb, struct sk_buff* old_skb)
{
	new_skb->tstamp		= old_skb->tstamp;
	new_skb->sk  		= old_skb->sk;
	new_skb->dev		= old_skb->dev;
	memcpy(new_skb->cb, old_skb->cb, sizeof(old_skb->cb));
	new_skb->queue_mapping = old_skb->queue_mapping;
	memcpy(&new_skb->headers, &old_skb->headers, sizeof(new_skb->headers));
	new_skb->protocol = htons(ETH_P_IP);
}

static inline bool skb_is_ipv4(struct sk_buff *skb)
{
    __be16 proto = skb->protocol;

    if (proto == htons(ETH_P_8021Q) ||
        proto == htons(ETH_P_8021AD)) {
        proto = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
    }

    return proto == htons(ETH_P_IP);
}

static inline struct iphdr *get_ipv4_hdr(struct sk_buff *skb)
{
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NULL;

    return ip_hdr(skb);
}


static inline bool skb_src_ip_match(struct sk_buff *skb)
{
    struct iphdr *iph;

    if (!skb_is_ipv4(skb))
        return false;

    iph = get_ipv4_hdr(skb);
    if (!iph)
        return false;
	// pr_info("iph->daddr %pI4\n", &iph->daddr);
    return iph->saddr == TARGET_IP;
}

static void debug_print_skb_layout(const struct sk_buff *skb, const char *msg)
{
    if (!skb) {
        pr_info("skb_debug: [%s] skb is NULL\n", msg);
        return;
    }

    pr_info("skb_debug: === [%s] Layout ===\n", msg);

    /* 1. 绝对指针地址 (Pointers) */
    pr_info("  Addresses: head=%px, data=%px, tail=%px, end=%px\n",
            skb->head, skb->data, skb_tail_pointer(skb), skb_end_pointer(skb));

    /* 2. 相对偏移量 (Offsets from head) */
    /* head 永远是 0 */
    pr_info("  Offsets:   head=0, data=%d, tail=%d, end=%d\n",
            (int)(skb->data - skb->head),
            (int)(skb_tail_pointer(skb) - skb->head),
            (int)(skb_end_offset(skb)));

    /* 3. 长度信息 (Lengths) */
    pr_info("  Lengths:   len=%u, data_len=%u, headlen=%u\n",
            skb->len, skb->data_len, skb_headlen(skb));

    /* 4. 剩余空间 (Room) */
    pr_info("  Room:      headroom=%u, tailroom=%u\n",
            skb_headroom(skb), skb_tailroom(skb));

    /* 5. 分片信息 (Non-linear info) */
    if (skb_is_nonlinear(skb)) {
        pr_info("  Non-linear: nr_frags=%u\n", skb_shinfo(skb)->nr_frags);
    } else {
        pr_info("  Non-linear: (Linear Only)\n");
    }

    pr_info("skb_debug: =========================\n");
}

void compare_skb_metadata(struct sk_buff *good_skb, struct sk_buff *test_skb) {
    pr_info("--- SKB Metadata Comparison ---\n");
    
    // 1. 长度与内存占用
    pr_info("%-20s | %-15s | %-15s\n", "Field", "Good SKB", "Test SKB");
    pr_info("----------------------------------------------------------\n");
    pr_info("%-20s | %-15u | %-15u\n", "len", good_skb->len, test_skb->len);
    pr_info("%-20s | %-15u | %-15u\n", "data_len", good_skb->data_len, test_skb->data_len);
    pr_info("%-20s | %-15u | %-15u\n", "truesize", good_skb->truesize, test_skb->truesize);
    
    // 2. 指针位置 (打印相对于 head 的偏移量更具对比价值)
    pr_info("%-20s | %-15ld | %-15ld\n", "head->data offset", 
            (long)(good_skb->data - good_skb->head), (long)(test_skb->data - test_skb->head));
    pr_info("%-20s | %-15ld | %-15ld\n", "head->tail offset", 
            (long)(skb_tail_pointer(good_skb) - good_skb->head), (long)(skb_tail_pointer(test_skb) - test_skb->head));
    
    // 3. 协议与类型
    pr_info("%-20s | 0x%-13x | 0x%-13x\n", "protocol", ntohs(good_skb->protocol), ntohs(test_skb->protocol));
    pr_info("%-20s | %-15u | %-15u\n", "pkt_type", good_skb->pkt_type, test_skb->pkt_type);
    
    // 4. 各层 Header 偏移量 (使用内核宏获取)
    pr_info("%-20s | %-15d | %-15d\n", "mac_header", skb_mac_header_was_set(good_skb) ? good_skb->mac_header : -1, 
                                             skb_mac_header_was_set(test_skb) ? test_skb->mac_header : -1);
    pr_info("%-20s | %-15d | %-15d\n", "network_header", good_skb->network_header, test_skb->network_header);
    pr_info("%-20s | %-15d | %-15d\n", "transport_header", good_skb->transport_header, test_skb->transport_header);

    // 5. 校验和状态
    pr_info("%-20s | %-15u | %-15u\n", "ip_summed", good_skb->ip_summed, test_skb->ip_summed);
    pr_info("%-20s | 0x%-13x | 0x%-13x\n", "csum", good_skb->csum, test_skb->csum);

    // 6. 关键设备指针
    pr_info("%-20s | %-15p | %-15p\n", "dev", good_skb->dev, test_skb->dev);
    
    // 7. 优先级与标志
    pr_info("%-20s | %-15u | %-15u\n", "priority", good_skb->priority, test_skb->priority);
    pr_info("%-20s | %-15u | %-15u\n", "mark", good_skb->mark, test_skb->mark);

    pr_info("--- End of Comparison ---\n");
}

static void print_skb_tcp_seq(struct sk_buff *skb, const char *msg)
{
    struct tcphdr *th;

    if (!skb) return;

    // 1. 获取 TCP 报头
    // 注意：这要求 skb->transport_header 已经被正确设置
    th = tcp_hdr(skb);

    // 2. 检查是否真的是 TCP 包（可选，取决于你调用该函数的位置）
    // 如果是在协议栈早期，可能需要先判断 iph->protocol == IPPROTO_TCP

    // 3. 提取序列号并进行字节序转换
    // TCP 序列号在网络中以大端序（Big Endian）存储
    // ntohl 用于将其转换为当前 CPU 的主机字节序
    uint32_t seq = ntohl(th->seq);
    uint32_t ack_seq = ntohl(th->ack_seq);

    pr_info("[%s] TCP Seq: %u, Ack-Seq: %u\n", msg, seq, ack_seq);
}

static int
br_netif_receive_skb(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	br_drop_fake_rtable(skb);
	#if RECV_FEATURE
		// ip header + tcp header + mac header = 20 + 32 + 14 = 66. Here uses a conservative value 80 to ensure that it's a data pkt but not a control pkt
		struct cxl_skb_ring *ring = cxl_offset_mem_addr;	
		static u32 current_tail;
		static u8 prev_mark = 0;	

		//TODO:use a better method find the flow we need 
		if(skb_src_ip_match(skb))
		{
			if(!ring->init_mark)
			{
				clflush(ring);
				goto original_path;
			}
			else if(prev_mark == 0)
			{
				clflush(ring);
				__rmb();
				current_tail = ring->tail;
				prev_mark = 1;
			}
			if(skb_headlen(skb) >= 80){

				u32 budget = 0;
				struct cxl_skb_entry entry;
				
				//get budget for this poll
				budget = get_ring_budget(ring, &current_tail);
				budget = (budget>4) ? 4 : budget;
				if(budget == 0)
				{
					pr_info("[br] no new message\n");
					goto drop;
				}
				// TODO: test skb clone by configure budget is 1

				u32 linear_size = skb_end_pointer(skb) - skb->head;
				// pr_info("[bridge_recv] linear size of skb %d\n", linear_size);
				struct sk_buff* new_skb;
				for (int i = 0; i < budget; i ++)
				{
					new_skb = alloc_skb(linear_size, GFP_KERNEL);
					skb_configure(new_skb, skb);
					ring_pop(ring, &entry, &current_tail);
					if(current_tail > 1){
						clflush(&ring->buf[current_tail-1]);
						__rmb();
						pr_info("AFTER:budget:%u,offset:0x%llx, size:%u, current_tail %u, tail in ring: %u\n",budget ,ring->buf[current_tail-1].header.offset, (ring->buf[current_tail-1]).header.size, current_tail ,ring->tail);
						// pr_info("ENTRY:offset:0x%llx, size:%u\n",entry.header.offset, entry.header.size);

					}
					copy_skb_whole_linear_with_shinfo(new_skb, entry.header.size, entry.header.offset);
					// content_test(entry.payload.pfn);
					replace_skb_with_cxl_page(new_skb, entry.payload.pfn, 0, entry.payload.size, entry.header.size - 14);
					// debug_print_skb_layout(new_skb,"bridge_input");
					// compare_skb_metadata(skb,new_skb);
					print_skb_tcp_seq(new_skb, "bridge_input");
					// kfree_skb(new_skb);
					// goto original_path;
					netif_receive_skb(new_skb);
					// kfree_skb(new_skb);
				}
				budget = 0;
				//TODO: current solution can confirm the sequence of pkts or not?
				goto drop;
				
			}
		}
		// struct cxl_skb_entry* entry = cxl_offset_mem_addr;
		// int pfn = entry->payload.pfn;
		// int size = entry->payload.size;
		// if (pfn != 0  && entry->header.sent_mark == 1 && skb_headlen(skb) >= 80){
		// 	entry->header.sent_mark = 0;
		// 	content_test(pfn);
		// 	replace_skb_with_cxl_page(skb, pfn, 0, size,entry->header.size - 14);
		// 	pr_info("[bridge_input]: replace done\n");
		// 	debug_print_skb_layout_in(skb,"br_input");
		// }	
		// else
		// 	pr_info("[bridge_input]: pfn is zero, can't replace page\n");
		// if(skb_headlen(skb) >= 80)
		// 	debug_print_skb_layout_in(skb,"br_input");

	#endif
original_path:
	return netif_receive_skb(skb);
drop:
	kfree_skb(skb);
	return 0;

}

static int br_pass_frame_up(struct sk_buff *skb)
{
	struct net_device *indev, *brdev = BR_INPUT_SKB_CB(skb)->brdev;
	struct net_bridge *br = netdev_priv(brdev);
	struct net_bridge_vlan_group *vg;

	dev_sw_netstats_rx_add(brdev, skb->len);

	vg = br_vlan_group_rcu(br);

	/* Reset the offload_fwd_mark because there could be a stacked
	 * bridge above, and it should not think this bridge it doing
	 * that bridge's work forwarding out its ports.
	 */
	br_switchdev_frame_unmark(skb);

	/* Bridge is just like any other port.  Make sure the
	 * packet is allowed except in promisc mode when someone
	 * may be running packet capture.
	 */
	if (!(brdev->flags & IFF_PROMISC) &&
	    !br_allowed_egress(vg, skb)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	indev = skb->dev;
	skb->dev = brdev;
	skb = br_handle_vlan(br, NULL, vg, skb);
	if (!skb)
		return NET_RX_DROP;
	/* update the multicast stats if the packet is IGMP/MLD */
	br_multicast_count(br, NULL, skb, br_multicast_igmp_type(skb),
			   BR_MCAST_DIR_TX);

	return NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,
		       dev_net(indev), NULL, skb, indev, NULL,
		       br_netif_receive_skb);
}

/* note: already called with rcu_read_lock */
int br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	enum br_pkt_type pkt_type = BR_PKT_UNICAST;
	struct net_bridge_fdb_entry *dst = NULL;
	struct net_bridge_mcast_port *pmctx;
	struct net_bridge_mdb_entry *mdst;
	bool local_rcv, mcast_hit = false;
	struct net_bridge_mcast *brmctx;
	struct net_bridge_vlan *vlan;
	struct net_bridge *br;
	u16 vid = 0;
	u8 state;

	if (!p)
		goto drop;

	br = p->br;

	if (br_mst_is_enabled(br)) {
		state = BR_STATE_FORWARDING;
	} else {
		if (p->state == BR_STATE_DISABLED)
			goto drop;

		state = p->state;
	}

	brmctx = &p->br->multicast_ctx;
	pmctx = &p->multicast_ctx;
	if (!br_allowed_ingress(p->br, nbp_vlan_group_rcu(p), skb, &vid,
				&state, &vlan))
		goto out;

	if (p->flags & BR_PORT_LOCKED) {
		struct net_bridge_fdb_entry *fdb_src =
			br_fdb_find_rcu(br, eth_hdr(skb)->h_source, vid);

		if (!fdb_src) {
			/* FDB miss. Create locked FDB entry if MAB is enabled
			 * and drop the packet.
			 */
			if (p->flags & BR_PORT_MAB)
				br_fdb_update(br, p, eth_hdr(skb)->h_source,
					      vid, BIT(BR_FDB_LOCKED));
			goto drop;
		} else if (READ_ONCE(fdb_src->dst) != p ||
			   test_bit(BR_FDB_LOCAL, &fdb_src->flags)) {
			/* FDB mismatch. Drop the packet without roaming. */
			goto drop;
		} else if (test_bit(BR_FDB_LOCKED, &fdb_src->flags)) {
			/* FDB match, but entry is locked. Refresh it and drop
			 * the packet.
			 */
			br_fdb_update(br, p, eth_hdr(skb)->h_source, vid,
				      BIT(BR_FDB_LOCKED));
			goto drop;
		}
	}

	nbp_switchdev_frame_mark(p, skb);

	/* insert into forwarding database after filtering to avoid spoofing */
	if (p->flags & BR_LEARNING)
		br_fdb_update(br, p, eth_hdr(skb)->h_source, vid, 0);

	local_rcv = !!(br->dev->flags & IFF_PROMISC);
	if (is_multicast_ether_addr(eth_hdr(skb)->h_dest)) {
		/* by definition the broadcast is also a multicast address */
		if (is_broadcast_ether_addr(eth_hdr(skb)->h_dest)) {
			pkt_type = BR_PKT_BROADCAST;
			local_rcv = true;
		} else {
			pkt_type = BR_PKT_MULTICAST;
			if (br_multicast_rcv(&brmctx, &pmctx, vlan, skb, vid))
				goto drop;
		}
	}

	if (state == BR_STATE_LEARNING)
		goto drop;

	BR_INPUT_SKB_CB(skb)->brdev = br->dev;
	BR_INPUT_SKB_CB(skb)->src_port_isolated = !!(p->flags & BR_ISOLATED);

	if (IS_ENABLED(CONFIG_INET) &&
	    (skb->protocol == htons(ETH_P_ARP) ||
	     skb->protocol == htons(ETH_P_RARP))) {
		br_do_proxy_suppress_arp(skb, br, vid, p);
	} else if (IS_ENABLED(CONFIG_IPV6) &&
		   skb->protocol == htons(ETH_P_IPV6) &&
		   br_opt_get(br, BROPT_NEIGH_SUPPRESS_ENABLED) &&
		   pskb_may_pull(skb, sizeof(struct ipv6hdr) +
				 sizeof(struct nd_msg)) &&
		   ipv6_hdr(skb)->nexthdr == IPPROTO_ICMPV6) {
			struct nd_msg *msg, _msg;

			msg = br_is_nd_neigh_msg(skb, &_msg);
			if (msg)
				br_do_suppress_nd(skb, br, vid, p, msg);
	}

	switch (pkt_type) {
	case BR_PKT_MULTICAST:
		mdst = br_mdb_entry_skb_get(brmctx, skb, vid);
		if ((mdst || BR_INPUT_SKB_CB_MROUTERS_ONLY(skb)) &&
		    br_multicast_querier_exists(brmctx, eth_hdr(skb), mdst)) {
			if ((mdst && mdst->host_joined) ||
			    br_multicast_is_router(brmctx, skb)) {
				local_rcv = true;
				DEV_STATS_INC(br->dev, multicast);
			}
			mcast_hit = true;
		} else {
			local_rcv = true;
			DEV_STATS_INC(br->dev, multicast);
		}
		break;
	case BR_PKT_UNICAST:
		dst = br_fdb_find_rcu(br, eth_hdr(skb)->h_dest, vid);
		break;
	default:
		break;
	}

	if (dst) {
		unsigned long now = jiffies;

		if (test_bit(BR_FDB_LOCAL, &dst->flags))
			return br_pass_frame_up(skb);

		if (now != dst->used)
			dst->used = now;
		br_forward(dst->dst, skb, local_rcv, false);
	} else {
		if (!mcast_hit)
			br_flood(br, skb, pkt_type, local_rcv, false, vid);
		else
			br_multicast_flood(mdst, skb, brmctx, local_rcv, false);
	}

	if (local_rcv)
		return br_pass_frame_up(skb);

out:
	return 0;
drop:
	kfree_skb(skb);
	goto out;
}
EXPORT_SYMBOL_GPL(br_handle_frame_finish);

static void __br_handle_local_finish(struct sk_buff *skb)
{
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	u16 vid = 0;

	/* check if vlan is allowed, to avoid spoofing */
	if ((p->flags & BR_LEARNING) &&
	    nbp_state_should_learn(p) &&
	    !br_opt_get(p->br, BROPT_NO_LL_LEARN) &&
	    br_should_learn(p, skb, &vid))
		br_fdb_update(p->br, p, eth_hdr(skb)->h_source, vid, 0);
}

/* note: already called with rcu_read_lock */
static int br_handle_local_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	__br_handle_local_finish(skb);

	/* return 1 to signal the okfn() was called so it's ok to use the skb */
	return 1;
}

static int nf_hook_bridge_pre(struct sk_buff *skb, struct sk_buff **pskb)
{
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
	struct nf_hook_entries *e = NULL;
	struct nf_hook_state state;
	unsigned int verdict, i;
	struct net *net;
	int ret;

	net = dev_net(skb->dev);
#ifdef HAVE_JUMP_LABEL
	if (!static_key_false(&nf_hooks_needed[NFPROTO_BRIDGE][NF_BR_PRE_ROUTING]))
		goto frame_finish;
#endif

	e = rcu_dereference(net->nf.hooks_bridge[NF_BR_PRE_ROUTING]);
	if (!e)
		goto frame_finish;

	nf_hook_state_init(&state, NF_BR_PRE_ROUTING,
			   NFPROTO_BRIDGE, skb->dev, NULL, NULL,
			   net, br_handle_frame_finish);

	for (i = 0; i < e->num_hook_entries; i++) {
		verdict = nf_hook_entry_hookfn(&e->hooks[i], skb, &state);
		switch (verdict & NF_VERDICT_MASK) {
		case NF_ACCEPT:
			if (BR_INPUT_SKB_CB(skb)->br_netfilter_broute) {
				*pskb = skb;
				return RX_HANDLER_PASS;
			}
			break;
		case NF_DROP:
			kfree_skb(skb);
			return RX_HANDLER_CONSUMED;
		case NF_QUEUE:
			ret = nf_queue(skb, &state, i, verdict);
			if (ret == 1)
				continue;
			return RX_HANDLER_CONSUMED;
		default: /* STOLEN */
			return RX_HANDLER_CONSUMED;
		}
	}
frame_finish:
	net = dev_net(skb->dev);
	br_handle_frame_finish(net, NULL, skb);
#else
	br_handle_frame_finish(dev_net(skb->dev), NULL, skb);
#endif
	return RX_HANDLER_CONSUMED;
}

/* Return 0 if the frame was not processed otherwise 1
 * note: already called with rcu_read_lock
 */
static int br_process_frame_type(struct net_bridge_port *p,
				 struct sk_buff *skb)
{
	struct br_frame_type *tmp;

	hlist_for_each_entry_rcu(tmp, &p->br->frame_type_list, list)
		if (unlikely(tmp->type == skb->protocol))
			return tmp->frame_handler(p, skb);

	return 0;
}

/*
 * Return NULL if skb is handled
 * note: already called with rcu_read_lock
 */
static rx_handler_result_t br_handle_frame(struct sk_buff **pskb)
{
	struct net_bridge_port *p;
	struct sk_buff *skb = *pskb;
	const unsigned char *dest = eth_hdr(skb)->h_dest;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	if (!is_valid_ether_addr(eth_hdr(skb)->h_source))
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return RX_HANDLER_CONSUMED;

	memset(skb->cb, 0, sizeof(struct br_input_skb_cb));
	br_tc_skb_miss_set(skb, false);

	p = br_port_get_rcu(skb->dev);
	if (p->flags & BR_VLAN_TUNNEL)
		br_handle_ingress_vlan_tunnel(skb, p, nbp_vlan_group_rcu(p));

	if (unlikely(is_link_local_ether_addr(dest))) {
		u16 fwd_mask = p->br->group_fwd_mask_required;

		/*
		 * See IEEE 802.1D Table 7-10 Reserved addresses
		 *
		 * Assignment		 		Value
		 * Bridge Group Address		01-80-C2-00-00-00
		 * (MAC Control) 802.3		01-80-C2-00-00-01
		 * (Link Aggregation) 802.3	01-80-C2-00-00-02
		 * 802.1X PAE address		01-80-C2-00-00-03
		 *
		 * 802.1AB LLDP 		01-80-C2-00-00-0E
		 *
		 * Others reserved for future standardization
		 */
		fwd_mask |= p->group_fwd_mask;
		switch (dest[5]) {
		case 0x00:	/* Bridge Group Address */
			/* If STP is turned off,
			   then must forward to keep loop detection */
			if (p->br->stp_enabled == BR_NO_STP ||
			    fwd_mask & (1u << dest[5]))
				goto forward;
			*pskb = skb;
			__br_handle_local_finish(skb);
			return RX_HANDLER_PASS;

		case 0x01:	/* IEEE MAC (Pause) */
			goto drop;

		case 0x0E:	/* 802.1AB LLDP */
			fwd_mask |= p->br->group_fwd_mask;
			if (fwd_mask & (1u << dest[5]))
				goto forward;
			*pskb = skb;
			__br_handle_local_finish(skb);
			return RX_HANDLER_PASS;

		default:
			/* Allow selective forwarding for most other protocols */
			fwd_mask |= p->br->group_fwd_mask;
			if (fwd_mask & (1u << dest[5]))
				goto forward;
		}

		/* The else clause should be hit when nf_hook():
		 *   - returns < 0 (drop/error)
		 *   - returns = 0 (stolen/nf_queue)
		 * Thus return 1 from the okfn() to signal the skb is ok to pass
		 */
		if (NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,
			    dev_net(skb->dev), NULL, skb, skb->dev, NULL,
			    br_handle_local_finish) == 1) {
			return RX_HANDLER_PASS;
		} else {
			return RX_HANDLER_CONSUMED;
		}
	}

	if (unlikely(br_process_frame_type(p, skb)))
		return RX_HANDLER_PASS;

forward:
	if (br_mst_is_enabled(p->br))
		goto defer_stp_filtering;

	switch (p->state) {
	case BR_STATE_FORWARDING:
	case BR_STATE_LEARNING:
defer_stp_filtering:
		if (ether_addr_equal(p->br->dev->dev_addr, dest))
			skb->pkt_type = PACKET_HOST;

		return nf_hook_bridge_pre(skb, pskb);
	default:
drop:
		kfree_skb(skb);
	}
	return RX_HANDLER_CONSUMED;
}

/* This function has no purpose other than to appease the br_port_get_rcu/rtnl
 * helpers which identify bridged ports according to the rx_handler installed
 * on them (so there _needs_ to be a bridge rx_handler even if we don't need it
 * to do anything useful). This bridge won't support traffic to/from the stack,
 * but only hardware bridging. So return RX_HANDLER_PASS so we don't steal
 * frames from the ETH_P_XDSA packet_type handler.
 */
static rx_handler_result_t br_handle_frame_dummy(struct sk_buff **pskb)
{
	return RX_HANDLER_PASS;
}

rx_handler_func_t *br_get_rx_handler(const struct net_device *dev)
{
	if (netdev_uses_dsa(dev))
		return br_handle_frame_dummy;

	return br_handle_frame;
}

void br_add_frame(struct net_bridge *br, struct br_frame_type *ft)
{
	hlist_add_head_rcu(&ft->list, &br->frame_type_list);
}

void br_del_frame(struct net_bridge *br, struct br_frame_type *ft)
{
	struct br_frame_type *tmp;

	hlist_for_each_entry(tmp, &br->frame_type_list, list)
		if (ft == tmp) {
			hlist_del_rcu(&ft->list);
			return;
		}
}
