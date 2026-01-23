// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	Forwarding decision
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 */

#include <linux/err.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netpoll.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/netfilter_bridge.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include "br_private.h"
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <asm/barrier.h>
#include <asm/special_insns.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>
#include <linux/atomic.h>

#define TARGET_IP htonl(0xC0A86403) /* 192.168.100.3 */

extern void* cxl_offset_mem_addr;

static u64 cxl_base_phys = 0xb90000000;

/* Don't forward packets to originating port or forwarding disabled */
static inline int should_deliver(const struct net_bridge_port *p,
				 const struct sk_buff *skb)
{
	struct net_bridge_vlan_group *vg;

	vg = nbp_vlan_group_rcu(p);
	return ((p->flags & BR_HAIRPIN_MODE) || skb->dev != p->dev) &&
		p->state == BR_STATE_FORWARDING && br_allowed_egress(vg, skb) &&
		nbp_switchdev_allowed_egress(p, skb) &&
		!br_skb_isolated(p, skb);
}

static void print_skb_payload(const struct sk_buff *skb)
{
    unsigned int hlen, offset, plen;
    unsigned char *buf;
    int i;

    /* transport header offset */
    offset = skb_transport_offset(skb);

    /* 如果没有传输层头（例如某些非IP包），跳过 */
    if (offset >= skb->len) {
        pr_info("skb has no transport header\n");
        return;
    }

    /* 传输层头部长度（TCP/UDP） */
    if (ip_hdr(skb)->protocol == IPPROTO_TCP)
        hlen = tcp_hdrlen(skb);
    else if (ip_hdr(skb)->protocol == IPPROTO_UDP)
        hlen = sizeof(struct udphdr);
    else
        hlen = 0;

    /* payload 起点 */
    offset += hlen;

    if (offset >= skb->len) {
        pr_info("skb has no payload\n");
        return;
    }

    /* payload 长度 */
    plen = skb->len - offset;

    pr_info("Payload length = %u\n", plen);

	if(skb_is_nonlinear(skb))
		pr_info("This is a nonlinear skb\n");
	else
		pr_info("This a linear skb\n");

    /* 分配临时 buffer 来 copy payload（skb 可能是非线性的） */
    buf = kmalloc(plen, GFP_ATOMIC);
    if (!buf)
        return;

    /* 复制 payload 数据，支持非线性 skb */
    if (skb_copy_bits(skb, offset, buf, plen) < 0) {
        pr_info("skb_copy_bits() failed\n");
        kfree(buf);
        return;
    }

    /* 以 hex 输出前 64 个字节（避免刷爆 dmesg） */
    {
        unsigned int dump_len = min(plen, 64u);
        pr_info("Payload first %u bytes:\n", dump_len);
        for (i = 0; i < dump_len; i++)
            pr_cont("%02x ", buf[i]);
        pr_cont("\n");
    }

    kfree(buf);
}

void dump_skb_frags(struct sk_buff *skb, struct cxl_skb_entry* entry)
{
    struct skb_shared_info *shinfo = skb_shinfo(skb);
    int i;
	
	void* data = skb->data;
	struct page* dp = virt_to_head_page(data);
	int node = page_to_nid(dp);
	// pr_info("[SKB DATA]  linear area:  data=%p node=%d phys=0x%llx size:%d\n",
	// 		data, node, (unsigned long long)virt_to_phys(data),skb_end_offset(skb));
	entry->header.offset = (unsigned long long)virt_to_phys(data) - cxl_base_phys;
	entry->header.size = skb_headlen(skb);
	entry->header.pfn = 0;
    // pr_info("nr_frags = %u\n", shinfo->nr_frags);
    for (i = 0; i < shinfo->nr_frags; i++) {
        skb_frag_t *f = &shinfo->frags[i];
        struct page *page = skb_frag_page(f);
		int nid = page_to_nid(page);
        phys_addr_t phys = (phys_addr_t)page_to_pfn(page) << PAGE_SHIFT;
		entry->payload.offset = phys - cxl_base_phys;
		entry->payload.pfn = page_to_pfn(page);
        // pr_info("frag[%d]: page=%p, page_phys=0x%llx, pfn=%d "
        //         "page_offset=%u, size=%u, order=%d,numanode_id=%d\n",
        //         i,
        //         page,
        //         (unsigned long long)phys,
		// 		page_to_pfn(page),
        //         skb_frag_off(f),
        //         skb_frag_size(f), 
		// 		compound_order(page),
		// 		nid);
		unsigned int offset = skb_frag_off(f);
		unsigned int size = skb_frag_size(f);
		entry->payload.size = skb->data_len;
		// entry->header.sent_mark = 1;

		// void *vaddr;

		// vaddr = kmap_local_page(page);
		// print_hex_dump(KERN_INFO,
		// 			"frag: ",
		// 			DUMP_PREFIX_OFFSET,
		// 			16, 1,
		// 			vaddr + offset,
		// 			min(size, 64U),
		// 			false);
		// kunmap_local(vaddr);
    }
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
static void ring_init(struct cxl_skb_ring * ring)
{
	ring->head = 0;
	ring->tail = 0;
	ring->init_mark = 1;
	clflush(ring);
	__wmb();
}
static int get_ring_budget(struct cxl_skb_ring* ring, u32* current_head)
{
	clflush(ring);
	u32 tail = ring->tail;
	// no space to write
	u32 next = ((*current_head)+1) % RING_SIZE;
	ring->head = *current_head;
	clflush(ring);
	__rmb();
	__wmb();
	if(next == tail)
		return 0;

	if(*current_head > tail)
		return ring->ring_size - next + tail;
	else
		return tail - next;
}

static void ring_push(struct cxl_skb_ring* ring, struct cxl_skb_entry* entry, u32* head)
{
	/*** TODO: current design can't support that there are many CPUs use this ring to push 
		 because maybe two CPUs read the same head 
	***/
	struct cxl_skb_entry* entry_in = &ring->buf[*head];
	entry_in->header.offset = entry->header.offset;
	entry_in->header.size = entry->header.size;
	
	entry_in->payload.pfn = entry->payload.pfn;
	entry_in->payload.size = entry->payload.size;
	clflush(entry_in);
	*head = ((*head) + 1) % RING_SIZE;
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


static inline bool skb_dst_ip_match(struct sk_buff *skb)
{
    struct iphdr *iph;

    if (!skb_is_ipv4(skb))
        return false;

    iph = get_ipv4_hdr(skb);
    if (!iph)
        return false;
	// pr_info("iph->daddr %pI4\n", &iph->daddr);
    return iph->daddr == TARGET_IP;
}



void print_skb_refcounts(struct sk_buff *skb, const char *location)
{
    if (!skb) {
        pr_info("[%s] SKB is NULL\n", location);
        return;
    }

    // 获取 sk_buff 结构体的引用计数
    int skb_users = refcount_read(&skb->users);

    // 获取数据缓冲区的引用计数
    // skb_shinfo 存储在数据缓冲区的末尾，用于管理共享数据
    int data_users = atomic_read(&skb_shinfo(skb)->dataref);

    pr_info("--- SKB Refcount Trace at [%s] ---\n", location);
    pr_info("SKB Address:  %p\n", skb);
    pr_info("Data Address: %p\n", skb->head);
    pr_info("skb->users:   %d (Header reference)\n", skb_users);
    pr_info("dataref:      %d (Data buffer reference)\n", data_users);
    
    // 如果是 TCP 包，还可以看看它是否有关联的 socket
    if (skb->sk) {
        pr_info("Associated Socket: %p\n", skb->sk);
    }
    pr_info("------------------------------------------\n");
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

int br_dev_queue_push_xmit(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	skb_push(skb, ETH_HLEN);
	if (!is_skb_forwardable(skb->dev, skb))
		goto drop;

	br_drop_fake_rtable(skb);

	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    eth_type_vlan(skb->protocol)) {
		int depth;

		if (!vlan_get_protocol_and_depth(skb, skb->protocol, &depth))
			goto drop;

		skb_set_network_header(skb, depth);
	}

	br_switchdev_frame_set_offload_fwd_mark(skb);
	#if SENDER_FEATURE    
	if(skb_dst_ip_match(skb))
	{
		if (skb_is_nonlinear(skb)) {
			static u32 budget = 0;
			static u32 head;
			struct cxl_skb_ring* ring = cxl_offset_mem_addr;
			struct cxl_skb_entry entry;

			if(ring->init_mark == 0)
			{
				ring_init(ring);
				head = 0;
			}


			if(budget == 0)
			{
				budget = get_ring_budget(ring, &head);
				budget = (budget > 4) ? 4 : budget;
				pr_info("[INTR sent]");
				goto original_path;
			}

			if(budget--)
			{
				dump_skb_frags(skb, &entry);
				ring_push(ring, &entry, &head);
				__wmb();	
				clflush(ring);
				__rmb();
				// pr_info("offset:0x%llx, size:%d, current_head %u, head in ring: %u\n", ring->buf[head-1].header.offset, ring->buf[head-1].header.size, head, ring->head);
				// print_skb_refcounts(skb, "bridge");
				// debug_print_skb_layout(skb, "br_forward");
				print_skb_tcp_seq(skb,"br_forward");
				goto drop;
			}
			else
				goto drop;
		}
	}
	#endif

original_path:
	dev_queue_xmit(skb);
	return 0;

drop:
	kfree_skb(skb);
	return 0;
}
EXPORT_SYMBOL_GPL(br_dev_queue_push_xmit);


int br_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	skb_clear_tstamp(skb);
	return NF_HOOK(NFPROTO_BRIDGE, NF_BR_POST_ROUTING,
		       net, sk, skb, NULL, skb->dev,
		       br_dev_queue_push_xmit);

}
EXPORT_SYMBOL_GPL(br_forward_finish);

static void __br_forward(const struct net_bridge_port *to,
			 struct sk_buff *skb, bool local_orig)
{
	struct net_bridge_vlan_group *vg;
	struct net_device *indev;
	struct net *net;
	int br_hook;

	/* Mark the skb for forwarding offload early so that br_handle_vlan()
	 * can know whether to pop the VLAN header on egress or keep it.
	 */
	nbp_switchdev_frame_mark_tx_fwd_offload(to, skb);

	vg = nbp_vlan_group_rcu(to);
	skb = br_handle_vlan(to->br, to, vg, skb);
	if (!skb)
		return;

	indev = skb->dev;
	skb->dev = to->dev;
	if (!local_orig) {
		if (skb_warn_if_lro(skb)) {
			kfree_skb(skb);
			return;
		}
		br_hook = NF_BR_FORWARD;
		skb_forward_csum(skb);
		net = dev_net(indev);
	} else {
		if (unlikely(netpoll_tx_running(to->br->dev))) {
			skb_push(skb, ETH_HLEN);
			if (!is_skb_forwardable(skb->dev, skb))
				kfree_skb(skb);
			else
				br_netpoll_send_skb(to, skb);
			return;
		}
		br_hook = NF_BR_LOCAL_OUT;
		net = dev_net(skb->dev);
		indev = NULL;
	}

	NF_HOOK(NFPROTO_BRIDGE, br_hook,
		net, NULL, skb, indev, skb->dev,
		br_forward_finish);
}

static int deliver_clone(const struct net_bridge_port *prev,
			 struct sk_buff *skb, bool local_orig)
{
	struct net_device *dev = BR_INPUT_SKB_CB(skb)->brdev;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb) {
		DEV_STATS_INC(dev, tx_dropped);
		return -ENOMEM;
	}

	__br_forward(prev, skb, local_orig);
	return 0;
}

/**
 * br_forward - forward a packet to a specific port
 * @to: destination port
 * @skb: packet being forwarded
 * @local_rcv: packet will be received locally after forwarding
 * @local_orig: packet is locally originated
 *
 * Should be called with rcu_read_lock.
 */
void br_forward(const struct net_bridge_port *to,
		struct sk_buff *skb, bool local_rcv, bool local_orig)
{
	if (unlikely(!to))
		goto out;

	/* redirect to backup link if the destination port is down */
	if (rcu_access_pointer(to->backup_port) && !netif_carrier_ok(to->dev)) {
		struct net_bridge_port *backup_port;

		backup_port = rcu_dereference(to->backup_port);
		if (unlikely(!backup_port))
			goto out;
		BR_INPUT_SKB_CB(skb)->backup_nhid = READ_ONCE(to->backup_nhid);
		to = backup_port;
	}

	if (should_deliver(to, skb)) {
		if (local_rcv)
			deliver_clone(to, skb, local_orig);
		else
			__br_forward(to, skb, local_orig);
		return;
	}

out:
	if (!local_rcv)
		kfree_skb(skb);
}
EXPORT_SYMBOL_GPL(br_forward);

static struct net_bridge_port *maybe_deliver(
	struct net_bridge_port *prev, struct net_bridge_port *p,
	struct sk_buff *skb, bool local_orig)
{
	u8 igmp_type = br_multicast_igmp_type(skb);
	int err;

	if (!should_deliver(p, skb))
		return prev;

	nbp_switchdev_frame_mark_tx_fwd_to_hwdom(p, skb);

	if (!prev)
		goto out;

	err = deliver_clone(prev, skb, local_orig);
	if (err)
		return ERR_PTR(err);
out:
	br_multicast_count(p->br, p, skb, igmp_type, BR_MCAST_DIR_TX);

	return p;
}

/* called under rcu_read_lock */
void br_flood(struct net_bridge *br, struct sk_buff *skb,
	      enum br_pkt_type pkt_type, bool local_rcv, bool local_orig,
	      u16 vid)
{
	struct net_bridge_port *prev = NULL;
	struct net_bridge_port *p;

	br_tc_skb_miss_set(skb, pkt_type != BR_PKT_BROADCAST);

	list_for_each_entry_rcu(p, &br->port_list, list) {
		/* Do not flood unicast traffic to ports that turn it off, nor
		 * other traffic if flood off, except for traffic we originate
		 */
		switch (pkt_type) {
		case BR_PKT_UNICAST:
			if (!(p->flags & BR_FLOOD))
				continue;
			break;
		case BR_PKT_MULTICAST:
			if (!(p->flags & BR_MCAST_FLOOD) && skb->dev != br->dev)
				continue;
			break;
		case BR_PKT_BROADCAST:
			if (!(p->flags & BR_BCAST_FLOOD) && skb->dev != br->dev)
				continue;
			break;
		}

		/* Do not flood to ports that enable proxy ARP */
		if (p->flags & BR_PROXYARP)
			continue;
		if (BR_INPUT_SKB_CB(skb)->proxyarp_replied &&
		    ((p->flags & BR_PROXYARP_WIFI) ||
		     br_is_neigh_suppress_enabled(p, vid)))
			continue;

		prev = maybe_deliver(prev, p, skb, local_orig);
		if (IS_ERR(prev))
			goto out;
	}

	if (!prev)
		goto out;

	if (local_rcv)
		deliver_clone(prev, skb, local_orig);
	else
		__br_forward(prev, skb, local_orig);
	return;

out:
	if (!local_rcv)
		kfree_skb(skb);
}

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
static void maybe_deliver_addr(struct net_bridge_port *p, struct sk_buff *skb,
			       const unsigned char *addr, bool local_orig)
{
	struct net_device *dev = BR_INPUT_SKB_CB(skb)->brdev;
	const unsigned char *src = eth_hdr(skb)->h_source;

	if (!should_deliver(p, skb))
		return;

	/* Even with hairpin, no soliloquies - prevent breaking IPv6 DAD */
	if (skb->dev == p->dev && ether_addr_equal(src, addr))
		return;

	skb = skb_copy(skb, GFP_ATOMIC);
	if (!skb) {
		DEV_STATS_INC(dev, tx_dropped);
		return;
	}

	if (!is_broadcast_ether_addr(addr))
		memcpy(eth_hdr(skb)->h_dest, addr, ETH_ALEN);

	__br_forward(p, skb, local_orig);
}

/* called with rcu_read_lock */
void br_multicast_flood(struct net_bridge_mdb_entry *mdst,
			struct sk_buff *skb,
			struct net_bridge_mcast *brmctx,
			bool local_rcv, bool local_orig)
{
	struct net_bridge_port *prev = NULL;
	struct net_bridge_port_group *p;
	bool allow_mode_include = true;
	struct hlist_node *rp;

	rp = br_multicast_get_first_rport_node(brmctx, skb);

	if (mdst) {
		p = rcu_dereference(mdst->ports);
		if (br_multicast_should_handle_mode(brmctx, mdst->addr.proto) &&
		    br_multicast_is_star_g(&mdst->addr))
			allow_mode_include = false;
	} else {
		p = NULL;
		br_tc_skb_miss_set(skb, true);
	}

	while (p || rp) {
		struct net_bridge_port *port, *lport, *rport;

		lport = p ? p->key.port : NULL;
		rport = br_multicast_rport_from_node_skb(rp, skb);

		if ((unsigned long)lport > (unsigned long)rport) {
			port = lport;

			if (port->flags & BR_MULTICAST_TO_UNICAST) {
				maybe_deliver_addr(lport, skb, p->eth_addr,
						   local_orig);
				goto delivered;
			}
			if ((!allow_mode_include &&
			     p->filter_mode == MCAST_INCLUDE) ||
			    (p->flags & MDB_PG_FLAGS_BLOCKED))
				goto delivered;
		} else {
			port = rport;
		}

		prev = maybe_deliver(prev, port, skb, local_orig);
		if (IS_ERR(prev))
			goto out;
delivered:
		if ((unsigned long)lport >= (unsigned long)port)
			p = rcu_dereference(p->next);
		if ((unsigned long)rport >= (unsigned long)port)
			rp = rcu_dereference(hlist_next_rcu(rp));
	}

	if (!prev)
		goto out;

	if (local_rcv)
		deliver_clone(prev, skb, local_orig);
	else
		__br_forward(prev, skb, local_orig);
	return;

out:
	if (!local_rcv)
		kfree_skb(skb);
}
#endif

