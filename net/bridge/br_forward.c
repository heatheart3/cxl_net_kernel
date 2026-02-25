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
#include "br_debug.h"
#include "br_cxl_net.h"
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <asm/barrier.h>
#include <asm/special_insns.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>
#include <linux/atomic.h>


extern void* cxl_offset_mem_addr;

static u64 cxl_base_phys = 0xb90000000;

static u8 timer_counter;


extern struct hrtimer budget_hrtimer;
extern struct tasklet_struct tx_flush_tasklet;

// struct sk_buff* intr_skb_template;

struct cxl_ring_sender ring2to3, ring3to2;
static bool cxl_tcp_parse(struct sk_buff *skb, struct tcphdr **th_out);

static const char *cxl_tcp_type(struct tcphdr *th, u16 payload_len)
{
	if (th->syn && th->ack)
		return "SYN-ACK";
	if (th->syn)
		return "SYN";
	if (th->fin && th->ack)
		return "FIN-ACK";
	if (th->fin)
		return "FIN";
	if (th->rst)
		return "RST";
	if (th->ack && payload_len == 0 && !th->psh)
		return "ACK-ONLY";
	if (payload_len > 0)
		return "DATA";

	return "OTHER";
}

static void cxl_log_tx_enqueue(struct sk_buff *skb, const char *tag,
			       struct cxl_skb_ring *ring, u32 head,
			       bool with_payload, u8 queue_id)
{
	struct tcphdr *th;
	struct iphdr *iph;
	u16 ip_len, tcph_len, payload_len;

	if (!cxl_tcp_parse(skb, &th))
		return;

	iph = ip_hdr(skb);
	if (!iph)
		return;

	ip_len = ntohs(iph->tot_len);
	tcph_len = th->doff * 4;
	payload_len = (ip_len > iph->ihl * 4 + tcph_len) ?
		      (ip_len - iph->ihl * 4 - tcph_len) : 0;

	pr_info("[cxl-tx:%s] q_id:%u type=%s %pI4:%u -> %pI4:%u datalen:%u seq=%u ack=%u payload=%u with_payload=%u head=%u tail=%u\n",
		tag,queue_id, cxl_tcp_type(th, payload_len),
		&iph->saddr, ntohs(th->source), &iph->daddr, ntohs(th->dest),skb_headlen(skb),
		ntohl(th->seq), ntohl(th->ack_seq), payload_len, with_payload,
		head, ring->tail);
}

static bool cxl_flow_ip_match(struct sk_buff *skb)
{
	bool d2 = skb_dst_ip_match(skb, 0xC0A86402); /* 192.168.100.2 */
	bool d3 = skb_dst_ip_match(skb, 0xC0A86403); /* 192.168.100.3 */
	bool s2 = skb_src_ip_match(skb, 0xC0A86402);
	bool s3 = skb_src_ip_match(skb, 0xC0A86403);

	return (s2 && d3) || (s3 && d2);
}

static bool cxl_tcp_parse(struct sk_buff *skb, struct tcphdr **th_out)
{
	struct iphdr *iph;
	struct tcphdr *th;
	unsigned int ihl_bytes;

	if (!skb || skb->protocol != htons(ETH_P_IP))
		return false;
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return false;

	iph = ip_hdr(skb);
	if (!iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
		return false;

	ihl_bytes = iph->ihl * 4;
	if (!pskb_may_pull(skb, ihl_bytes + sizeof(struct tcphdr)))
		return false;

	iph = ip_hdr(skb);
	th = (struct tcphdr *)((u8 *)iph + ihl_bytes);
	if (th_out)
		*th_out = th;
	return true;
}

static bool cxl_tcp_teardown(struct sk_buff *skb)
{
	struct tcphdr *th;

	if (!cxl_tcp_parse(skb, &th))
		return false;

	return th->fin;
}

static bool cxl_fastpath_eligible(struct sk_buff *skb)
{
	struct tcphdr *th;

	if (!cxl_flow_ip_match(skb))
		return false;
	if (!cxl_tcp_parse(skb, &th))
		return false;

	/* Keep 3-way handshake and 4-way teardown on normal NIC path. */
	if (th->syn || th->fin || th->rst)
		return false;

	return true;
}

static struct cxl_skb_ring *cxl_ring_get_by_dst(struct sk_buff *skb)
{
	struct cxl_skb_ring *ring_base = (struct cxl_skb_ring *)cxl_offset_mem_addr;

	if (skb_dst_ip_match(skb, 0xC0A86403)) /* 192.168.100.3 */
		return &ring_base[0];

	return &ring_base[1];
}



static inline void budget_timer_start(void)
{
    hrtimer_start(&budget_hrtimer, ns_to_ktime(BUDGET_TIMEOUT_NS),
                  HRTIMER_MODE_REL);
}


void send_intr_skb(struct sk_buff* intr_skb_template)
{
	struct sk_buff *skb_to_send;
	unsigned long flags;

	if (!intr_skb_template)
		return;

	skb_to_send = skb_copy(intr_skb_template, GFP_ATOMIC);

	if (!skb_to_send)
		return;

	skb_to_send->dev = intr_skb_template->dev;

	dev_queue_xmit(skb_to_send);
}

void tx_flush_tasklet_func(unsigned long data)
{
	// send_intr_skb();
}

enum hrtimer_restart budget_timer_cb(struct hrtimer *t)
{
	pr_info("timer cb triggered\n");
	tasklet_schedule(&tx_flush_tasklet);
	if(timer_counter < 3){
		hrtimer_forward_now(t, ns_to_ktime(BUDGET_TIMEOUT_NS));
		timer_counter++;
		return HRTIMER_RESTART;
	}
	return HRTIMER_NORESTART;
}


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


void dump_skb_frags(struct sk_buff *skb, struct cxl_skb_entry* entry)
{
    struct skb_shared_info *shinfo = skb_shinfo(skb);	

    for (int i = 0; i < shinfo->nr_frags; i++) {
        skb_frag_t *f = &shinfo->frags[i];
        struct page *page = skb_frag_page(f);
        phys_addr_t phys = (phys_addr_t)page_to_pfn(page) << PAGE_SHIFT;
		entry->payload.offset = skb_frag_off(f);
		entry->payload.pfn = page_to_pfn(page);
		entry->payload.size = skb->data_len;
    }
}


static void ring_init(struct cxl_skb_ring * ring)
{
	ring->head = 0;
	ring->tail = 0;
	ring->init_mark = 1;
	ring->ring_size = RING_SIZE;
	clflush(ring);
	__wmb();
}
static void ring_deinit(struct cxl_skb_ring* ring)
{
	ring->init_mark = 0;
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
	// pr_info("[get_ring_budget] head :%u, tail:%u\n",next, tail);
	if(next == tail)
		return 0;

	if(*current_head > tail)
		return ring->ring_size - next + tail;
	else
		return tail - next;
}



static void ring_push(struct cxl_skb_ring* ring, u32* head, struct sk_buff* skb, u8 queue_id)
{
	/*** TODO: current design can't support that there are many CPUs use this ring to push 
		 because maybe two CPUs read the same head 
	***/
	struct cxl_skb_entry* entry_in = &ring->buf[*head];

	// dump payload into CXL mem
	if(skb_is_nonlinear(skb))
	{
		entry_in->header.with_payload = 1;
		dump_skb_frags(skb, entry_in);
	}
	else
		entry_in->header.with_payload = 0;
	// pr_info("[ring_push] with_payload:%u\n", entry_in->header.with_payload);
	// Copy header to CXL mem
	entry_in->header.size = skb_headlen(skb);
	memcpy(entry_in->header.content, skb->data, skb_headlen(skb));
	void* p = entry_in;
	clflush(p);
	clflush(p + 64);
	clflush(p + 128);
	__wmb();
	// pr_info("[ring_push] head:%u buffer size%u\n",*head,entry_in->header.size);

	*head = ((*head) + 1) % RING_SIZE;

	// cxl_log_tx_enqueue(skb, "enqueue", ring, *head, entry_in->header.with_payload,queue_id);
}

static int update_intr_skb_template(struct sk_buff *skb, struct sk_buff **intr_skb_template)
{
	struct sk_buff *tmpl;
	struct tcphdr* th;
	struct iphdr* iph;
	unsigned char* ptr;

	
	if(!skb)
	{
		pr_info("source is null\n");
		return -ENOMEM;
	}
	if (!intr_skb_template)
		return -EINVAL;

	tmpl = skb_copy(skb, GFP_ATOMIC);
	if (!tmpl)
	{
		pr_info("fail to copy\n");
		return -ENOMEM;
	}
	th = tcp_hdr(tmpl);
    iph = ip_hdr(tmpl);

    // 3. 将六个经典标志位全部置为 0
    // 这包括：FIN, SYN, RST, PSH, ACK, URG
    // 我们直接操作 tcphdr 结构体中的位域
    th->fin = 0;
    th->syn = 0;
    th->rst = 0;
    th->psh = 0;
    th->ack = 0;
    th->urg = 0;

	ptr = (unsigned char *)(th + 1);
	if (th->doff <= 13)
		th->doff += 2;
	ptr = ptr + 12;
    // 4. 填充 RFC 6994 格式内容
    ptr[0] = 254;        // Kind: Experimental
    ptr[1] = 8;          // Length: 8 字节
    ptr[2] = 0x12;       // ExID 高位 (自定义魔数)
    ptr[3] = 0x34;       // ExID 低位
    ptr[4] = 0xAA;       // 你的自定义实验数据 1
    ptr[5] = 0xBB;       // 你的自定义实验数据 2
    ptr[6] = 0xCC;       // 你的自定义实验数据 3
    ptr[7] = 0xDD;       // 你的自定义实验数据 4
		
	if (*intr_skb_template)
		kfree_skb(*intr_skb_template);
	*intr_skb_template = tmpl;

	return 0;
}

struct cxl_skb_ring* alloc_ring(void)
{
	struct cxl_skb_ring* alloced_cxl_mem = cxl_offset_mem_addr;
	static u32 alloc_cnt = 0;
	alloc_cnt ++;
	return (alloced_cxl_mem + alloc_cnt);
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


	if (cxl_flow_ip_match(skb))
	{	
		struct cxl_ring_sender* ring_sender;

		if(skb_dst_ip_match(skb, 0xC0A86403))
		{
			ring_sender = &ring2to3;
			ring_sender->src = 2;
		}
		else{
			ring_sender = &ring3to2;
			ring_sender->src = 3;
		}

		if(ring_sender->c_status == CONNECTION_CLOSED)
		{
			// pr_info("s_r_s:%u connection status:%u\n",ring_sender->src, ring_sender->c_status);

			if(skb_tcp_debug_handler(skb, SKB_TCP_CHECK_SYN, "br_dev_queue_push_xmit"))
			{
				ring_sender->c_status = CONNECTION_HALF_OPEN;  // half connected
				//TODO: there is a mem leak because intr_skb hasn't a method to release when unmount the module
				int ret = update_intr_skb_template(skb, &ring_sender->intr_skb_template);
				// pr_info("ret %d\n", ret);
				// pr_info("s_r_s:%u, connection status:%u\n",ring_sender->src, ring_sender->c_status);
			}
			goto original_path;
		}
		if(ring_sender->c_status == CONNECTION_HALF_OPEN)
		{
			if(cxl_fastpath_eligible(skb))
			{
				ring_sender->c_status = CONNECTION_OPEN;
				// pr_info("s_r_s:%u, connection status:%u\n",ring_sender->src,ring_sender->c_status);
				ring_sender->ring = cxl_ring_get_by_dst(skb);
				ring_init(ring_sender->ring);
				ring_sender->current_head = 0;
				ring_sender->send_budget = 0;
			}
			else 
				goto original_path;
		}
		if(ring_sender->c_status == CONNECTION_OPEN)
		{
			if(cxl_tcp_teardown(skb))
			{
				ring_sender->c_status = CONNECTION_CLOSED;
				if(ring_sender->intr_skb_template)
					kfree_skb(ring_sender->intr_skb_template);
				ring_deinit(ring_sender->ring);
				// pr_info("s_r_s:%u, connection status:%u\n",ring_sender->src, ring_sender->c_status);
				goto original_path;
			}
		}

		if(ring_sender->c_status == CONNECTION_CLOSED)
			goto original_path;

		if(ring_sender->c_status == CONNECTION_OPEN){
			if (cxl_fastpath_eligible(skb)) {
				
				clflush(ring_sender->ring);
				__rmb();
				if (ring_sender->send_budget == 0 ) {
					ring_sender->send_budget = get_ring_budget(ring_sender->ring, &ring_sender->current_head);
					ring_sender->send_budget = (ring_sender->send_budget > 4) ? 4 : ring_sender->send_budget;
					if(!ring_sender->intr_skb_template)
						pr_info("NULL intr_skb\n");
					send_intr_skb(ring_sender->intr_skb_template);
					// hrtimer_cancel(&budget_hrtimer);
					// timer_counter = 0;
					// budget_timer_start();
				}

				if (ring_sender->send_budget > 0)
				{
					ring_sender->send_budget--;
					// skb_debug_dump(skb, SKB_NONLINEAR, "SKB_DEBUG_DUMP");
					ring_push(ring_sender->ring, &ring_sender->current_head, skb, ring_sender->src);
					__wmb();
					clflush(ring_sender->ring);
					__rmb();
					// pr_info("current_head %u, head in ring: %u\n", ring_sender->current_head, ring_sender->ring->head);
					// print_skb_refcounts(skb, "bridge");
					// skb_debug_dump(skb,SKB_METADATA_LAYOUT, "SKB_DEBUG_DUMP");
					// skb_tcp_debug_handler(skb, SKB_TCP_PRINT_SEQ, "SKB_TCP_DEBUG_HANDLER");
					goto drop;
				}
			}
		}
		// goto drop;
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
