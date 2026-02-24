
#include "br_debug.h"



static bool skb_is_ipv4(struct sk_buff *skb)
{
    __be16 proto = skb->protocol;

    if (proto == htons(ETH_P_8021Q) ||
        proto == htons(ETH_P_8021AD)) {
        proto = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
    }

    return proto == htons(ETH_P_IP);
}


bool skb_src_ip_match(struct sk_buff *skb, u32 ip)
{
    struct iphdr *iph;

    if (!skb_is_ipv4(skb))
        return false;

    iph = ip_hdr(skb);
    if (!iph)
        return false;
    return iph->saddr == htonl(ip);
}

bool skb_dst_ip_match(struct sk_buff *skb, u32 ip)
{
    struct iphdr *iph;

    if (!skb_is_ipv4(skb))
        return false;

    iph = ip_hdr(skb);
    if (!iph)
        return false;
    return iph->daddr == htonl(ip);
}


bool skb_tcp_debug_handler(struct sk_buff *skb,
                    enum skb_tcp_debug_op op,
                    const char *msg)
{
    struct iphdr *iph;
    struct tcphdr *th;
    unsigned int ihl_bytes;

    if (!skb)
        return false;

    /* 1️⃣ 必须是 IPv4 */
    if (skb->protocol != htons(ETH_P_IP))
        return false;

    /* 2️⃣ 确保 IP 头在可访问范围 */
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return false;

    iph = ip_hdr(skb);

    if (iph->version != 4)
        return false;

    if (iph->protocol != IPPROTO_TCP)
        return false;

    ihl_bytes = iph->ihl * 4;

    /* 3️⃣ 确保 TCP 头在可访问范围 */
    if (!pskb_may_pull(skb, ihl_bytes + sizeof(struct tcphdr)))
        return false;

    /* ⚠️ 重新获取指针（可能被 pskb_may_pull 改变） */
    iph = ip_hdr(skb);
    th  = (struct tcphdr *)((u8 *)iph + ihl_bytes);

    /* 4️⃣ 根据 op 执行 */
    switch (op) {

    case SKB_TCP_PRINT_SEQ: {
        u32 seq = ntohl(th->seq);
        u32 ack_seq = ntohl(th->ack_seq);

        pr_info("[%s] TCP Seq: %u, Ack-Seq: %u\n",
                msg ? msg : "skb",
                seq, ack_seq);
                
        return false;
    }

    case SKB_TCP_CHECK_FIN:
        return !!th->fin;
    
    case SKB_TCP_CHECK_SYN:
        return !!th->syn;

    case SKB_TCP_CHECK_ACK:
        return !!th->ack;
    
        
    }

    return false;
}


void skb_debug_dump(struct sk_buff *skb,
                    enum skb_debug_op op,
                    const char *msg)
{
    struct skb_shared_info *shinfo;
    const char *tag = msg ? msg : "skb";
    int i;

    if (!skb) {
        pr_info("skb_debug: [%s] skb is NULL\n", tag);
        return;
    }

    pr_info("skb_debug: === [%s] begin (op=0x%x) ===\n", tag, op);

    /* -------------------- 1) Layout -------------------- */
    if (op & SKB_METADATA_LAYOUT) {
        pr_info("skb_debug: --- [%s] Layout ---\n", tag);

        pr_info("  Addresses: head=%px, data=%px, tail=%px, end=%px\n",
                skb->head, skb->data, skb_tail_pointer(skb), skb_end_pointer(skb));

        pr_info("  Offsets:   head=0, data=%d, tail=%d, end=%d\n",
                (int)(skb->data - skb->head),
                (int)(skb_tail_pointer(skb) - skb->head),
                (int)skb_end_offset(skb));

        pr_info("  Lengths:   len=%u, data_len=%u, headlen=%u\n",
                skb->len, skb->data_len, skb_headlen(skb));

        pr_info("  Room:      headroom=%u, tailroom=%u\n",
                skb_headroom(skb), skb_tailroom(skb));

        if (skb_is_nonlinear(skb))
            pr_info("  Non-linear: nr_frags=%u\n", skb_shinfo(skb)->nr_frags);
        else
            pr_info("  Non-linear: (Linear Only)\n");
    }

    /* -------------------- 2) Non-linear dump -------------------- */
    if (op & SKB_NONLINEAR) {
        shinfo = skb_shinfo(skb);

        pr_info("skb_debug: --- [%s] Non-linear dump ---\n", tag);

        if (!skb_is_nonlinear(skb) && !shinfo->frag_list) {
            pr_info("[%s] SKB has no non-linear data (linear && no frag_list).\n", tag);
            goto out;
        }

        /* 2.1 paged frags: shinfo->frags[] */
        if (skb_is_nonlinear(skb)) {
            pr_info("[%s] nr_frags=%u\n", tag, shinfo->nr_frags);

            for (i = 0; i < shinfo->nr_frags; i++) {
                skb_frag_t *frag = &shinfo->frags[i];
                unsigned int len = skb_frag_size(frag);
                unsigned int off = skb_frag_off(frag);
                struct page *page = skb_frag_page(frag);
                unsigned long pfn;
                phys_addr_t phys_addr;
                void *vaddr;
                unsigned int dump_len;

                if (!page) {
                    pr_info("[%s] frag[%d]: page=NULL\n", tag, i);
                    continue;
                }

                pfn = page_to_pfn(page);
                phys_addr = page_to_phys(page) + off;

                pr_info("[%s] frag[%d]: size=%u off=%u PFN=%lu phys=%pa\n",
                        tag, i, len, off, pfn, &phys_addr);

                /* 限制 dump 长度，避免刷屏 */
                dump_len = len;
                if (dump_len > SKB_PAYLOAD_MAX_BYTES)
                    dump_len = SKB_PAYLOAD_MAX_BYTES;

                vaddr = kmap_atomic(page);
                print_hex_dump(KERN_INFO, "  Frag Data: ", DUMP_PREFIX_OFFSET,
                               16, 1, (u8 *)vaddr + off, dump_len, true);
                kunmap_atomic(vaddr);

                if (len > dump_len)
                    pr_info("[%s] frag[%d]: (truncated %u -> %u bytes)\n",
                            tag, i, len, dump_len);
            }
        }

        /* 2.2 frag_list */
        if (shinfo->frag_list) {
            struct sk_buff *list_skb;

            pr_info("[%s] Found frag_list elements.\n", tag);

            skb_walk_frags(skb, list_skb) {
                unsigned int dump_len = skb_headlen(list_skb);

                if (dump_len > SKB_PAYLOAD_MAX_BYTES)
                    dump_len = SKB_PAYLOAD_MAX_BYTES;

                pr_info("[%s] list_skb len=%u headlen=%u data_len=%u\n",
                        tag, list_skb->len, skb_headlen(list_skb), list_skb->data_len);

                print_hex_dump(KERN_INFO, "  List Data: ", DUMP_PREFIX_OFFSET,
                               16, 1, list_skb->data, dump_len, true);

                if (skb_headlen(list_skb) > dump_len)
                    pr_info("[%s] list_skb: (truncated %u -> %u bytes)\n",
                            tag, skb_headlen(list_skb), dump_len);
            }
        }
    }

out:
    pr_info("skb_debug: === [%s] end ===\n", tag);
}
                

void skb_metadata_compare(struct sk_buff *first_skb, struct sk_buff* second_skb){
        pr_info("--- [SKB_Metadata_Compare] ---\n");
    
    // 1. 长度与内存占用
    pr_info("%-20s | %-15s | %-15s\n", "Field", "First SKB", "Second SKB");
    pr_info("----------------------------------------------------------\n");
    pr_info("%-20s | %-15u | %-15u\n", "len", first_skb->len, second_skb->len);
    pr_info("%-20s | %-15u | %-15u\n", "data_len", first_skb->data_len, second_skb->data_len);
    pr_info("%-20s | %-15u | %-15u\n", "truesize", first_skb->truesize, second_skb->truesize);
    
    // 2. 指针位置 (打印相对于 head 的偏移量更具对比价值)
    pr_info("%-20s | %-15ld | %-15ld\n", "head->data offset", 
            (long)(first_skb->data - first_skb->head), (long)(second_skb->data - second_skb->head));
    pr_info("%-20s | %-15ld | %-15ld\n", "head->tail offset", 
            (long)(skb_tail_pointer(first_skb) - first_skb->head), (long)(skb_tail_pointer(second_skb) - second_skb->head));
    
    // 3. 协议与类型
    pr_info("%-20s | 0x%-13x | 0x%-13x\n", "protocol", ntohs(first_skb->protocol), ntohs(second_skb->protocol));
    pr_info("%-20s | %-15u | %-15u\n", "pkt_type", first_skb->pkt_type, second_skb->pkt_type);
    
    // 4. 各层 Header 偏移量 (使用内核宏获取)
    pr_info("%-20s | %-15d | %-15d\n", "mac_header", skb_mac_header_was_set(first_skb) ? first_skb->mac_header : -1, 
                                             skb_mac_header_was_set(second_skb) ? second_skb->mac_header : -1);
    pr_info("%-20s | %-15d | %-15d\n", "network_header", first_skb->network_header, second_skb->network_header);
    pr_info("%-20s | %-15d | %-15d\n", "transport_header", first_skb->transport_header, second_skb->transport_header);

    // 5. 校验和状态
    pr_info("%-20s | %-15u | %-15u\n", "ip_summed", first_skb->ip_summed, second_skb->ip_summed);
    pr_info("%-20s | 0x%-13x | 0x%-13x\n", "csum", first_skb->csum, second_skb->csum);

    // 6. 关键设备指针
    pr_info("%-20s | %-15p | %-15p\n", "dev", first_skb->dev, second_skb->dev);
    
    // 7. 优先级与标志
    pr_info("%-20s | %-15u | %-15u\n", "priority", first_skb->priority, second_skb->priority);
    pr_info("%-20s | %-15u | %-15u\n", "mark", first_skb->mark, second_skb->mark);

    pr_info("--- End of Comparison ---\n");
}