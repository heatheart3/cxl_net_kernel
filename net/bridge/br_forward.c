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
#include <linux/inet.h>
#include "br_private.h"
#include <linux/mm.h>
#include <linux/memcontrol.h>


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

void dump_skb_frags(struct sk_buff *skb)
{
    struct skb_shared_info *shinfo = skb_shinfo(skb);
    int i;
	
    // pr_info("nr_frags = %u\n", shinfo->nr_frags);

    for (i = 0; i < shinfo->nr_frags; i++) {
        skb_frag_t *f = &shinfo->frags[i];
        struct page *page = skb_frag_page(f);
		int nid = page_to_nid(page);
        phys_addr_t phys = (phys_addr_t)page_to_pfn(page) << PAGE_SHIFT;

        pr_info("frag[%d]: page=%p, page_phys=0x%llx, "
                "page_offset=%u, size=%u, numanode_id=%d\n",
                i,
                page,
                (unsigned long long)phys,
                skb_frag_off(f),
                skb_frag_size(f), nid);
    }
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

	// print_skb_payload(skb);
	dump_skb_frags(skb);

    /* 否则正常转发并打印 */
    // pr_info("bridge: packet xmit via %s, len=%u, src=%pM dst=%pM, src=%pI4 dst=%pI4\n",
    //         skb->dev->name, skb->len,
    //         eth->h_source, eth->h_dest,
    //         &iph->saddr, &iph->daddr);

	dev_queue_xmit(skb);

	// pr_info("bridge: packet xmit via %s, len=%u, src=%pM dst=%pM, src=%pI4, dst=%pI4\n",
	// 	skb->dev->name, skb->len,
	// 	eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr);

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

