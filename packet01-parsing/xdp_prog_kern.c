/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

// for loop unrolling
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

#define VLAN_VID_MASK 0x0fff /* VLAN identifier */
// struct for collecting vlans after parsing
struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
			  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr,
					struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	#pragma unroll
	for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
		// skip if not vlan
		if (!proto_is_vlan(h_proto))
			break;
		// skip if out of bounds
		if (vlh + 1 > data_end)
			break;
		
		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) /* collect VLAN ids */
			vlans->id[i] = (bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);
		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;

	if (ip6h + 1 > data_end)
		return -1;
	
	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

/* ipv4 support */
static __always_inline int parse_iphdr(struct hdr_cursor *nh, void *data_end, struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	// normal iphdr payload bounds check
	if (iph + 1 > data_end)
		return -1;
	
	// additional verify fullsize header fits in packet
	hdrsize = iph->ihl * 4;
	// ensure packet field is valid
	if (hdrsize < sizeof(*iph))
		return -1;
	if (nh->pos + hdrsize > data_end)
		return -1;
	
	// increment as usual
	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;

	if (icmp6h + 1 > data_end)
		return -1;

	nh->pos = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

/* ipv4 support */
static __always_inline int parse_icmphdr(struct hdr_cursor *nh, void *data_end, struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = nh->pos;

	if (icmph + 1 > data_end)
		return -1;

	nh->pos = icmph + 1;
	*icmphdr = icmph;
	return icmph->type;
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6hdr;
	struct iphdr *iphdr;
	struct icmp6hdr *icmp6hdr;
	struct icmphdr *icmphdr;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type, ip_type, icmp_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */

	/* Step 1: parse the ethernet header and return the next header type.
	 * If the next header type is an IPV6 header, continue, otherwise drop out.
	*/
	nh_type = parse_ethhdr(&nh, data_end, &eth); // stores header type
	if (nh_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	// Step 2: parse the ip header and increment the *nh to the icmp header
	// for step 3
	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ip6hdr);
	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else {
		goto out;
	}

	// Step 3: parse the icmp header, and check the sequence number.
	// Drop the packet if the sequence number is even.
	if (ip_type == IPPROTO_ICMPV6)
	{
		icmp_type = parse_icmp6hdr(&nh, data_end, &icmp6hdr);
		if (icmp6hdr + 1 > data_end)
			goto out;
		if (bpf_ntohs(icmp6hdr->icmp6_sequence) % 2 == 0)
			action = XDP_DROP;
	}
	else if (ip_type == IPPROTO_ICMP)
	{
		icmp_type = parse_icmphdr(&nh, data_end, &icmphdr);
		if (icmphdr + 1 > data_end)
			goto out;
		
		if (icmphdr->type == ICMP_ECHO || icmphdr->type == ICMP_ECHOREPLY) {
			if (bpf_ntohs(icmphdr->un.echo.sequence) % 2 == 0)
				action = XDP_DROP;
		}
	}
	else
	{
		goto out;
	}

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
