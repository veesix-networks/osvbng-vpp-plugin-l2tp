/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * L2TPv2 raw-mode egress graph node.
 *
 * Sibling to the midchain encap used by DECAP_IP sessions. The
 * midchain works for LNS (per-session vnet interface anchors the
 * adjacency); for LAC there is no vnet interface — PPP frames arrive
 * here directly from the PPPoE plugin's decap when `is_lac_tunneled`
 * is set.
 *
 * Buffer at entry: positioned at the PPP frame (starts with the 2-byte
 * PPP protocol field). `vnet_buffer_l2tpv2_opaque(b)` carries the L2TP
 * session index. We look up the session + tunnel, prepend IP+UDP+L2TP
 * encap, and forward to ip4-lookup — which then resolves the route to
 * the peer IP (loopback or otherwise) via FIB, and ARP/glean for the
 * final L2 next-hop.
 *
 * IP source/dest, UDP ports, and the receiver-assigned tunnel/session
 * IDs come from the session record; IP/UDP lengths are computed per
 * packet from buffer length.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip4.h>
#include <vnet/udp/udp_packet.h>
#include <l2tpv2/l2tpv2.h>

typedef struct
{
  u16 flags_ver;
  u16 tunnel_id;
  u16 session_id;
} __attribute__ ((packed)) l2tpv2_data_header_t;

#define L2TPV2_FLAGS_VER_DATA 0x0002

typedef struct
{
  u32 session_index;
  u32 tunnel_index;
  u16 peer_tunnel_id;
  u16 peer_session_id;
  u32 error;
} l2tpv2_encap_raw_trace_t;

static u8 *
format_l2tpv2_encap_raw_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2tpv2_encap_raw_trace_t *t =
    va_arg (*args, l2tpv2_encap_raw_trace_t *);

  s = format (s,
	      "l2tpv2-encap-raw session_index %d tunnel_index %d "
	      "peer-tid %d peer-sid %d error %d",
	      t->session_index, t->tunnel_index, t->peer_tunnel_id,
	      t->peer_session_id, t->error);
  return s;
}

#define foreach_l2tpv2_encap_raw_next                                          \
  _ (DROP, "error-drop")                                                       \
  _ (IP4_LOOKUP, "ip4-lookup")

typedef enum
{
#define _(s, n) L2TPV2_ENCAP_RAW_NEXT_##s,
  foreach_l2tpv2_encap_raw_next
#undef _
    L2TPV2_ENCAP_RAW_N_NEXT,
} l2tpv2_encap_raw_next_t;

VLIB_NODE_FN (l2tpv2_encap_raw_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  l2tpv2_main_t *l2m = &l2tpv2_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_encap = 0;
  u32 pkts_dropped = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = L2TPV2_ENCAP_RAW_NEXT_DROP;
	  u32 error0 = 0;
	  u32 session_index;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  session_index = vnet_buffer_l2tpv2_opaque (b0);
	  if (PREDICT_FALSE (session_index == ~0u
			     || pool_is_free_index (l2m->sessions,
						    session_index)))
	    {
	      error0 = L2TPV2_ERROR_NO_SUCH_SESSION;
	      pkts_dropped++;
	      goto trace00;
	    }

	  l2tpv2_session_t *s =
	    pool_elt_at_index (l2m->sessions, session_index);
	  l2tpv2_tunnel_t *t =
	    pool_elt_at_index (l2m->tunnels, s->tunnel_index);

	  /* Make room for IP + UDP + L2TP headers. The buffer has
	   * VLIB_BUFFER_PRE_DATA_SIZE bytes of pre-data headroom before
	   * b->data; current_data can go as low as
	   * -VLIB_BUFFER_PRE_DATA_SIZE. The previous check
	   * `current_data < encap_len` was wrong — it required the encap
	   * to fit in pre-current_data space, but the correct constraint
	   * is that the prepended encap fits in the pre-data headroom. */
	  u32 encap_len = sizeof (ip4_header_t) + sizeof (udp_header_t)
			  + sizeof (l2tpv2_data_header_t);
	  if (PREDICT_FALSE ((i32) b0->current_data - (i32) encap_len
			     < -(i32) VLIB_BUFFER_PRE_DATA_SIZE))
	    {
	      error0 = L2TPV2_ERROR_TRUNCATED;
	      pkts_dropped++;
	      goto trace00;
	    }
	  vlib_buffer_advance (b0, -(i32) encap_len);

	  ip4_header_t *ip = vlib_buffer_get_current (b0);
	  udp_header_t *udp = (udp_header_t *) (ip + 1);
	  l2tpv2_data_header_t *l2tp = (l2tpv2_data_header_t *) (udp + 1);
	  u16 packet_len = vlib_buffer_length_in_chain (vm, b0);

	  ip->ip_version_and_header_length = 0x45;
	  ip->tos = 0;
	  ip->length = clib_host_to_net_u16 (packet_len);
	  ip->fragment_id = 0;
	  ip->flags_and_fragment_offset =
	    t->df_bit ? clib_host_to_net_u16 (0x4000) : 0;
	  ip->ttl = 64;
	  ip->protocol = IP_PROTOCOL_UDP;
	  ip->checksum = 0;
	  ip->src_address.as_u32 = t->local_ip.as_u32;
	  ip->dst_address.as_u32 = t->peer_ip.as_u32;
	  ip->checksum = ip4_header_checksum (ip);

	  udp->src_port = clib_host_to_net_u16 (t->local_udp_port);
	  udp->dst_port = clib_host_to_net_u16 (t->peer_udp_port);
	  udp->length =
	    clib_host_to_net_u16 (packet_len - sizeof (ip4_header_t));
	  udp->checksum = 0;

	  l2tp->flags_ver = clib_host_to_net_u16 (L2TPV2_FLAGS_VER_DATA);
	  l2tp->tunnel_id = clib_host_to_net_u16 (t->peer_tunnel_id);
	  l2tp->session_id = clib_host_to_net_u16 (s->peer_session_id);

	  /* Use the tunnel's encap FIB for the ip4-lookup that follows. */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = t->encap_fib_index;

	  next0 = L2TPV2_ENCAP_RAW_NEXT_IP4_LOOKUP;
	  pkts_encap++;

	trace00:
	  b0->error = error0 ? node->errors[error0] : 0;
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2tpv2_encap_raw_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->session_index = session_index;
	      tr->tunnel_index = (error0 == 0) ? l2m->sessions[session_index]
						   .tunnel_index
					       : ~0;
	      tr->peer_tunnel_id =
		(error0 == 0)
		  ? l2m->tunnels[l2m->sessions[session_index].tunnel_index]
		      .peer_tunnel_id
		  : 0;
	      tr->peer_session_id = (error0 == 0)
				      ? l2m->sessions[session_index]
					  .peer_session_id
				      : 0;
	      tr->error = error0;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       L2TPV2_ERROR_DECAPSULATED, pkts_encap);
  vlib_node_increment_counter (vm, node->node_index,
			       L2TPV2_ERROR_NO_SUCH_SESSION, pkts_dropped);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (l2tpv2_encap_raw_node) = {
  .name = "l2tpv2-encap-raw",
  .vector_size = sizeof (u32),
  .n_errors = L2TPV2_N_ERROR,
  .error_strings = l2tpv2_error_strings,
  .n_next_nodes = L2TPV2_ENCAP_RAW_N_NEXT,
  .next_nodes = {
#define _(s, n) [L2TPV2_ENCAP_RAW_NEXT_##s] = n,
    foreach_l2tpv2_encap_raw_next
#undef _
  },
  .format_trace = format_l2tpv2_encap_raw_trace,
};
