/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * L2TPv2 egress encap rewrite and per-packet fixup.
 *
 * The midchain adjacency installed on the per-session vnet interface
 * uses the rewrite produced by l2tpv2_build_rewrite — IP + UDP +
 * L2TPv2 header — and then stacks on the FIB-contributed DPO for the
 * peer IP. That stacking is what makes peer IPs reachable via loopback
 * addresses or any routed path: VPP's FIB resolves the L2 next-hop at
 * lookup time, not at session creation time.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip4.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_midchain.h>
#include <l2tpv2/l2tpv2.h>

/* L2TPv2 data header: flags|ver(2 bytes) + tunnel_id(2) + session_id(2). */
typedef struct
{
  u16 flags_ver;
  u16 tunnel_id;
  u16 session_id;
} __attribute__ ((packed)) l2tpv2_data_header_t;

#define L2TPV2_FLAGS_VER_DATA 0x0002 /* version 2, no L/S/O/P flags */

u8 *
l2tpv2_build_rewrite (vnet_main_t *vnm, u32 sw_if_index, vnet_link_t link_type,
		      const void *dst_address)
{
  l2tpv2_main_t *l2m = &l2tpv2_main;
  l2tpv2_session_t *s;
  l2tpv2_tunnel_t *t;
  u8 *rw = 0;
  ip4_header_t *ip;
  udp_header_t *udp;
  l2tpv2_data_header_t *l2tp;

  if (sw_if_index >= vec_len (l2m->session_index_by_sw_if_index))
    return NULL;
  u32 sess_index = l2m->session_index_by_sw_if_index[sw_if_index];
  if (sess_index == ~0)
    return NULL;
  s = pool_elt_at_index (l2m->sessions, sess_index);
  t = pool_elt_at_index (l2m->tunnels, s->tunnel_index);

  int len = sizeof (ip4_header_t) + sizeof (udp_header_t)
	    + sizeof (l2tpv2_data_header_t);
  vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

  ip = (ip4_header_t *) rw;
  ip->ip_version_and_header_length = 0x45;
  ip->tos = 0;
  ip->length = 0;
  ip->fragment_id = 0;
  ip->flags_and_fragment_offset =
    t->df_bit ? clib_host_to_net_u16 (0x4000) : 0;
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->checksum = 0;
  ip->src_address.as_u32 = t->local_ip.as_u32;
  ip->dst_address.as_u32 = t->peer_ip.as_u32;

  udp = (udp_header_t *) (ip + 1);
  udp->src_port = clib_host_to_net_u16 (t->local_udp_port);
  udp->dst_port = clib_host_to_net_u16 (t->peer_udp_port);
  udp->length = 0;
  udp->checksum = 0;

  l2tp = (l2tpv2_data_header_t *) (udp + 1);
  l2tp->flags_ver = clib_host_to_net_u16 (L2TPV2_FLAGS_VER_DATA);
  l2tp->tunnel_id = clib_host_to_net_u16 (t->peer_tunnel_id);
  l2tp->session_id = clib_host_to_net_u16 (s->peer_session_id);

  return rw;
}

void
l2tpv2_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b0,
	      const void *data)
{
  ip4_header_t *ip0;
  udp_header_t *udp0;
  u16 packet_len = vlib_buffer_length_in_chain (vm, b0);

  ip0 = vlib_buffer_get_current (b0);
  ip0->length = clib_host_to_net_u16 (packet_len);
  ip0->checksum = ip4_header_checksum (ip0);

  udp0 = (udp_header_t *) (ip0 + 1);
  udp0->length = clib_host_to_net_u16 (packet_len - sizeof (ip4_header_t));
}
