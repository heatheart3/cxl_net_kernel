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
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <asm/barrier.h>
#include <asm/special_insns.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>
#include <linux/atomic.h>


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



static void ring_push(struct cxl_skb_ring* ring, struct cxl_skb_entry* entry, u32* head, struct sk_buff* skb)
{
	/*** TODO: current design can't support that there are many CPUs use this ring to push 
		 because maybe two CPUs read the same head 
	***/
	struct cxl_skb_entry* entry_in = &ring->buf[*head];
	dump_skb_frags(skb, entry_in);
	entry_in->header.size = skb_headlen(skb);
	memcpy(entry_in->header.content, skb->data, skb_headlen(skb));
	void* p = entry_in;
	clflush(p);
	clflush(p + 64);
	clflush(p + 128);
	__wmb();
	// pr_info("[ring_push] head:%u buffer size%u\n",*head,entry_in->header.size);

	*head = ((*head) + 1) % RING_SIZE;
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
	if(skb_dst_ip_match(skb, 0xC0A86403))
	{	
		static u32 budget = 0;
		static u32 head;
		struct cxl_skb_ring* ring = cxl_offset_mem_addr;
		static u32 init_mark = 0;
		struct cxl_skb_entry entry;
		//TODO: this part logic isn't enough, should stop all the pkts transmitting by the CXL mem after receiving a fin pkt
		if(skb_tcp_debug_handler(skb, SKB_TCP_CHECK_FIN, "SKB_TCP_DEBUG"))
		{
			ring_init(ring);
			head = 0;
			budget = 0;
			pr_info("[br_dev_queue_push_xmit]recv fin\n");
			clflush(ring); 
			__wmb();
		}
		if (skb_is_nonlinear(skb)) {

			clflush(ring);
			__rmb();
			if(init_mark == 0)
			{
				ring_init(ring);
				init_mark = 1;
				head = 0;
			}

			if(budget == 0)
			{
				budget = get_ring_budget(ring, &head);
				budget = (budget > 4) ? 4 : budget;
				// pr_info("[INTR sent]");
				// pr_info("budget:%u\n", budget);
				goto original_path;
			}

			if(budget--)
			{
				// dump_skb_frags(skb, &entry);
				skb_debug_dump(skb, SKB_NONLINEAR, "SKB_DEBUG_DUMP");
				ring_push(ring, &entry, &head,skb);
				__wmb();	
				clflush(ring);
				__rmb();
				pr_info("current_head %u, head in ring: %u\n", head, ring->head);
				// print_skb_refcounts(skb, "bridge");
				// skb_debug_dump(skb,SKB_METADATA_LAYOUT, "SKB_DEBUG_DUMP");
				// skb_tcp_debug_handler(skb, SKB_TCP_PRINT_SEQ, "SKB_TCP_DEBUG_HANDLER");
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

