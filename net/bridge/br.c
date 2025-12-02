// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	Generic parts
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/llc.h>
#include <net/llc.h>
#include <net/stp.h>
#include <net/switchdev.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/numa.h>
#include <linux/sched.h>
#include <linux/topology.h>

#include "br_private.h"

/*
 * Handle changes in state of network devices enslaved to a bridge.
 *
 * Note: don't care about up/down if bridge itself is down, because
 *     port state is checked when bridge is brought up.
 */
static int br_device_event(struct notifier_block *unused, unsigned long event, void *ptr)
{
	struct netlink_ext_ack *extack = netdev_notifier_info_to_extack(ptr);
	struct netdev_notifier_pre_changeaddr_info *prechaddr_info;
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct net_bridge_port *p;
	struct net_bridge *br;
	bool notified = false;
	bool changed_addr;
	int err;

	if (netif_is_bridge_master(dev)) {
		err = br_vlan_bridge_event(dev, event, ptr);
		if (err)
			return notifier_from_errno(err);

		if (event == NETDEV_REGISTER) {
			/* register of bridge completed, add sysfs entries */
			err = br_sysfs_addbr(dev);
			if (err)
				return notifier_from_errno(err);

			return NOTIFY_DONE;
		}
	}

	/* not a port of a bridge */
	p = br_port_get_rtnl(dev);
	if (!p)
		return NOTIFY_DONE;

	br = p->br;

	switch (event) {
	case NETDEV_CHANGEMTU:
		br_mtu_auto_adjust(br);
		break;

	case NETDEV_PRE_CHANGEADDR:
		if (br->dev->addr_assign_type == NET_ADDR_SET)
			break;
		prechaddr_info = ptr;
		err = dev_pre_changeaddr_notify(br->dev,
						prechaddr_info->dev_addr,
						extack);
		if (err)
			return notifier_from_errno(err);
		break;

	case NETDEV_CHANGEADDR:
		spin_lock_bh(&br->lock);
		br_fdb_changeaddr(p, dev->dev_addr);
		changed_addr = br_stp_recalculate_bridge_id(br);
		spin_unlock_bh(&br->lock);

		if (changed_addr)
			call_netdevice_notifiers(NETDEV_CHANGEADDR, br->dev);

		break;

	case NETDEV_CHANGE:
		br_port_carrier_check(p, &notified);
		break;

	case NETDEV_FEAT_CHANGE:
		netdev_update_features(br->dev);
		break;

	case NETDEV_DOWN:
		spin_lock_bh(&br->lock);
		if (br->dev->flags & IFF_UP) {
			br_stp_disable_port(p);
			notified = true;
		}
		spin_unlock_bh(&br->lock);
		break;

	case NETDEV_UP:
		if (netif_running(br->dev) && netif_oper_up(dev)) {
			spin_lock_bh(&br->lock);
			br_stp_enable_port(p);
			notified = true;
			spin_unlock_bh(&br->lock);
		}
		break;

	case NETDEV_UNREGISTER:
		br_del_if(br, dev);
		break;

	case NETDEV_CHANGENAME:
		err = br_sysfs_renameif(p);
		if (err)
			return notifier_from_errno(err);
		break;

	case NETDEV_PRE_TYPE_CHANGE:
		/* Forbid underlying device to change its type. */
		return NOTIFY_BAD;

	case NETDEV_RESEND_IGMP:
		/* Propagate to master device */
		call_netdevice_notifiers(event, br->dev);
		break;
	}

	if (event != NETDEV_UNREGISTER)
		br_vlan_port_event(p, event);

	/* Events that may cause spanning tree to refresh */
	if (!notified && (event == NETDEV_CHANGEADDR || event == NETDEV_UP ||
			  event == NETDEV_CHANGE || event == NETDEV_DOWN))
		br_ifinfo_notify(RTM_NEWLINK, NULL, p);

	return NOTIFY_DONE;
}

static struct notifier_block br_device_notifier = {
	.notifier_call = br_device_event
};

/* called with RTNL or RCU */
static int br_switchdev_event(struct notifier_block *unused,
			      unsigned long event, void *ptr)
{
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);
	struct net_bridge_port *p;
	struct net_bridge *br;
	struct switchdev_notifier_fdb_info *fdb_info;
	int err = NOTIFY_DONE;

	p = br_port_get_rtnl_rcu(dev);
	if (!p)
		goto out;

	br = p->br;

	switch (event) {
	case SWITCHDEV_FDB_ADD_TO_BRIDGE:
		fdb_info = ptr;
		err = br_fdb_external_learn_add(br, p, fdb_info->addr,
						fdb_info->vid,
						fdb_info->locked, false);
		if (err) {
			err = notifier_from_errno(err);
			break;
		}
		br_fdb_offloaded_set(br, p, fdb_info->addr,
				     fdb_info->vid, fdb_info->offloaded);
		break;
	case SWITCHDEV_FDB_DEL_TO_BRIDGE:
		fdb_info = ptr;
		err = br_fdb_external_learn_del(br, p, fdb_info->addr,
						fdb_info->vid, false);
		if (err)
			err = notifier_from_errno(err);
		break;
	case SWITCHDEV_FDB_OFFLOADED:
		fdb_info = ptr;
		br_fdb_offloaded_set(br, p, fdb_info->addr,
				     fdb_info->vid, fdb_info->offloaded);
		break;
	case SWITCHDEV_FDB_FLUSH_TO_BRIDGE:
		fdb_info = ptr;
		/* Don't delete static entries */
		br_fdb_delete_by_port(br, p, fdb_info->vid, 0);
		break;
	}

out:
	return err;
}

static struct notifier_block br_switchdev_notifier = {
	.notifier_call = br_switchdev_event,
};

/* called under rtnl_mutex */
static int br_switchdev_blocking_event(struct notifier_block *nb,
				       unsigned long event, void *ptr)
{
	struct netlink_ext_ack *extack = netdev_notifier_info_to_extack(ptr);
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);
	struct switchdev_notifier_brport_info *brport_info;
	const struct switchdev_brport *b;
	struct net_bridge_port *p;
	int err = NOTIFY_DONE;

	p = br_port_get_rtnl(dev);
	if (!p)
		goto out;

	switch (event) {
	case SWITCHDEV_BRPORT_OFFLOADED:
		brport_info = ptr;
		b = &brport_info->brport;

		err = br_switchdev_port_offload(p, b->dev, b->ctx,
						b->atomic_nb, b->blocking_nb,
						b->tx_fwd_offload, extack);
		err = notifier_from_errno(err);
		break;
	case SWITCHDEV_BRPORT_UNOFFLOADED:
		brport_info = ptr;
		b = &brport_info->brport;

		br_switchdev_port_unoffload(p, b->ctx, b->atomic_nb,
					    b->blocking_nb);
		break;
	case SWITCHDEV_BRPORT_REPLAY:
		brport_info = ptr;
		b = &brport_info->brport;

		err = br_switchdev_port_replay(p, b->dev, b->ctx, b->atomic_nb,
					       b->blocking_nb, extack);
		err = notifier_from_errno(err);
		break;
	}

out:
	return err;
}

static struct notifier_block br_switchdev_blocking_notifier = {
	.notifier_call = br_switchdev_blocking_event,
};

/* br_boolopt_toggle - change user-controlled boolean option
 *
 * @br: bridge device
 * @opt: id of the option to change
 * @on: new option value
 * @extack: extack for error messages
 *
 * Changes the value of the respective boolean option to @on taking care of
 * any internal option value mapping and configuration.
 */
int br_boolopt_toggle(struct net_bridge *br, enum br_boolopt_id opt, bool on,
		      struct netlink_ext_ack *extack)
{
	int err = 0;

	switch (opt) {
	case BR_BOOLOPT_NO_LL_LEARN:
		br_opt_toggle(br, BROPT_NO_LL_LEARN, on);
		break;
	case BR_BOOLOPT_MCAST_VLAN_SNOOPING:
		err = br_multicast_toggle_vlan_snooping(br, on, extack);
		break;
	case BR_BOOLOPT_MST_ENABLE:
		err = br_mst_set_enabled(br, on, extack);
		break;
	default:
		/* shouldn't be called with unsupported options */
		WARN_ON(1);
		break;
	}

	return err;
}

int br_boolopt_get(const struct net_bridge *br, enum br_boolopt_id opt)
{
	switch (opt) {
	case BR_BOOLOPT_NO_LL_LEARN:
		return br_opt_get(br, BROPT_NO_LL_LEARN);
	case BR_BOOLOPT_MCAST_VLAN_SNOOPING:
		return br_opt_get(br, BROPT_MCAST_VLAN_SNOOPING_ENABLED);
	case BR_BOOLOPT_MST_ENABLE:
		return br_opt_get(br, BROPT_MST_ENABLED);
	default:
		/* shouldn't be called with unsupported options */
		WARN_ON(1);
		break;
	}

	return 0;
}

int br_boolopt_multi_toggle(struct net_bridge *br,
			    struct br_boolopt_multi *bm,
			    struct netlink_ext_ack *extack)
{
	unsigned long bitmap = bm->optmask;
	int err = 0;
	int opt_id;

	for_each_set_bit(opt_id, &bitmap, BR_BOOLOPT_MAX) {
		bool on = !!(bm->optval & BIT(opt_id));

		err = br_boolopt_toggle(br, opt_id, on, extack);
		if (err) {
			br_debug(br, "boolopt multi-toggle error: option: %d current: %d new: %d error: %d\n",
				 opt_id, br_boolopt_get(br, opt_id), on, err);
			break;
		}
	}

	return err;
}

void br_boolopt_multi_get(const struct net_bridge *br,
			  struct br_boolopt_multi *bm)
{
	u32 optval = 0;
	int opt_id;

	for (opt_id = 0; opt_id < BR_BOOLOPT_MAX; opt_id++)
		optval |= (br_boolopt_get(br, opt_id) << opt_id);

	bm->optval = optval;
	bm->optmask = GENMASK((BR_BOOLOPT_MAX - 1), 0);
}

/* private bridge options, controlled by the kernel */
void br_opt_toggle(struct net_bridge *br, enum net_bridge_opts opt, bool on)
{
	bool cur = !!br_opt_get(br, opt);

	br_debug(br, "toggle option: %d state: %d -> %d\n",
		 opt, cur, on);

	if (cur == on)
		return;

	if (on)
		set_bit(opt, &br->options);
	else
		clear_bit(opt, &br->options);
}

static void __net_exit br_net_exit_batch(struct list_head *net_list)
{
	struct net_device *dev;
	struct net *net;
	LIST_HEAD(list);

	rtnl_lock();

	list_for_each_entry(net, net_list, exit_list)
		for_each_netdev(net, dev)
			if (netif_is_bridge_master(dev))
				br_dev_delete(dev, &list);

	unregister_netdevice_many(&list);

	rtnl_unlock();
}

static struct pernet_operations br_net_ops = {
	.exit_batch	= br_net_exit_batch,
};

static const struct stp_proto br_stp_proto = {
	.rcv	= br_stp_rcv,
};

void* vaddr_cxl;
u64 used_size;

void cxl_mem_init(void)
{
	phys_addr_t phys_base = (phys_addr_t)0xb90000000;
	u64 mapped_size = 2ULL * 1024 * 1024;
	vaddr_cxl = memremap(phys_base, mapped_size, MEMREMAP_WB);
    if (!vaddr_cxl) {
        pr_err("[br_cxl_init] memremap failed\n");
        return;
    }

	pr_info("[br_cxl_init] mapped   : va_base=%p  ~  va_end=%p\n",
                vaddr_cxl, (void *)((char *)vaddr_cxl + mapped_size - 1));
	u32 user_va, rb;
	*(u32 *)user_va = 8;
	rb = *(u32 *)user_va;
    pr_info("[br_cxl_init] wrote 0x%x, read back 0x%x\n", 8, rb);
}

void cxl_mem_deinit(void)
{
	if (vaddr_cxl) {
        memunmap(vaddr_cxl);
        vaddr_cxl = NULL;
    }
    pr_info("[br_cxl_deinit] unmapped and exit\n");
}
static struct kmem_cache *cxl_test_cache;
static void test_cxl_slab_alloc(int node_id, size_t size)
{
    void *obj;
    struct page *pg;
    phys_addr_t phys;

    printk(KERN_INFO "[CXL-SLAB-TEST] Creating kmem_cache(size=%zu)\n", size);

    cxl_test_cache = kmem_cache_create("cxl_slab_test_cache",
                                       size,
                                       0,
                                       SLAB_HWCACHE_ALIGN,
                                       NULL);
    if (!cxl_test_cache) {
        printk(KERN_ERR "[CXL-SLAB-TEST] kmem_cache_create failed.\n");
        return;
    }
    printk(KERN_INFO "[CXL-SLAB-TEST] Allocating from node %d ...\n", node_id);

    obj = kmem_cache_alloc_node(cxl_test_cache, GFP_HIGHUSER_MOVABLE, node_id);
    if (!obj) {
        printk(KERN_ERR "[CXL-SLAB-TEST] kmem_cache_alloc_node FAILED on node %d\n",
               node_id);
        goto out;
    }

    pg = virt_to_page(obj);
    phys = page_to_phys(pg);

    printk(KERN_INFO "[CXL-SLAB-TEST] Allocation succeeded!\n");
    printk(KERN_INFO "[CXL-SLAB-TEST] Virtual addr: %px\n", obj);
    printk(KERN_INFO "[CXL-SLAB-TEST] Page frame number: %lu\n", page_to_pfn(pg));
    printk(KERN_INFO "[CXL-SLAB-TEST] Physical addr: 0x%llx\n", (unsigned long long) phys);
    printk(KERN_INFO "[CXL-SLAB-TEST] Allocated on NUMA node: %d\n", page_to_nid(pg));

    if (page_to_nid(pg) == node_id)
        printk(KERN_INFO "[CXL-SLAB-TEST] SUCCESS: Slab allocated on CXL node %d!\n", node_id);
    else
        printk(KERN_WARNING "[CXL-SLAB-TEST] WARNING: Slab NOT allocated on requested node %d.\n",
                            node_id);

out:
    if (cxl_test_cache) {
        kmem_cache_destroy(cxl_test_cache);
        cxl_test_cache = NULL;
    }
}


void show_zonelist(void)
{
	int nid;

    for (nid = 0; nid < nr_node_ids; nid++) {
        struct zonelist *zl;
        struct zoneref *zref;
        int gfp_idx = gfp_zonelist(GFP_KERNEL);

        pr_info("=== NUMA Node %d ===\n", nid);
        zl = NODE_DATA(nid)->node_zonelists + gfp_idx;

        for (zref = zl->_zonerefs; zref->zone; zref++) {
            struct zone *z = zref->zone;
            pr_info("  zonelist entry: node %d zone %s\n",
                    zone_to_nid(z),
                    z->name);
        }
    }

}
void test_alloc_from_cxl(void)
{
	int nid = 1; // 你的 CXL node
    struct page *page;

    // 试一个“可移动”的分配
    page = alloc_pages_node(nid, GFP_HIGHUSER_MOVABLE, 0);
    if (!page) {
        pr_info("alloc_pages_node(%d, GFP_HIGHUSER_MOVABLE) failed\n", nid);
    }
	phys_addr_t phys = (phys_addr_t)page_to_pfn(page) << PAGE_SHIFT;
	pr_info("CXL frag: page=%p, page_phys=0x%llx\n",page,(unsigned long long)phys);
    pr_info("GFP_HIGHUSER_MOVABLE: got page on nid=%d\n", page_to_nid(page));

    __free_pages(page, 0);
}



static int __init br_init(void)
{
	int err;

	BUILD_BUG_ON(sizeof(struct br_input_skb_cb) > sizeof_field(struct sk_buff, cb));

	err = stp_proto_register(&br_stp_proto);
	if (err < 0) {
		pr_err("bridge: can't register sap for STP\n");
		return err;
	}

	// cxl_mem_init();
	// show_zonelist();
	// test_alloc_from_cxl();

	test_cxl_slab_alloc(1, 256);

	err = br_fdb_init();
	if (err)
		goto err_out;

	err = register_pernet_subsys(&br_net_ops);
	if (err)
		goto err_out1;

	err = br_nf_core_init();
	if (err)
		goto err_out2;

	err = register_netdevice_notifier(&br_device_notifier);
	if (err)
		goto err_out3;

	err = register_switchdev_notifier(&br_switchdev_notifier);
	if (err)
		goto err_out4;

	err = register_switchdev_blocking_notifier(&br_switchdev_blocking_notifier);
	if (err)
		goto err_out5;

	err = br_netlink_init();
	if (err)
		goto err_out6;

	brioctl_set(br_ioctl_stub);

#if IS_ENABLED(CONFIG_ATM_LANE)
	br_fdb_test_addr_hook = br_fdb_test_addr;
#endif

#if IS_MODULE(CONFIG_BRIDGE_NETFILTER)
	pr_info("bridge: filtering via arp/ip/ip6tables is no longer available "
		"by default. Update your scripts to load br_netfilter if you "
		"need this.\n");
#endif

	return 0;

err_out6:
	unregister_switchdev_blocking_notifier(&br_switchdev_blocking_notifier);
err_out5:
	unregister_switchdev_notifier(&br_switchdev_notifier);
err_out4:
	unregister_netdevice_notifier(&br_device_notifier);
err_out3:
	br_nf_core_fini();
err_out2:
	unregister_pernet_subsys(&br_net_ops);
err_out1:
	br_fdb_fini();
err_out:
	stp_proto_unregister(&br_stp_proto);
	return err;
}

static void __exit br_deinit(void)
{
	cxl_mem_deinit();
	stp_proto_unregister(&br_stp_proto);
	br_netlink_fini();
	unregister_switchdev_blocking_notifier(&br_switchdev_blocking_notifier);
	unregister_switchdev_notifier(&br_switchdev_notifier);
	unregister_netdevice_notifier(&br_device_notifier);
	brioctl_set(NULL);
	unregister_pernet_subsys(&br_net_ops);

	rcu_barrier(); /* Wait for completion of call_rcu()'s */

	br_nf_core_fini();
#if IS_ENABLED(CONFIG_ATM_LANE)
	br_fdb_test_addr_hook = NULL;
#endif
	br_fdb_fini();
}

module_init(br_init)
module_exit(br_deinit)
MODULE_LICENSE("GPL");
MODULE_VERSION(BR_VERSION);
MODULE_ALIAS_RTNL_LINK("bridge");
MODULE_DESCRIPTION("Ethernet bridge driver");

