/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * L2TPv2 data input graph node.
 *
 * Entered from the punt plugin's UDP/1701 demux on a T=0 packet. The
 * buffer is positioned at the L2TP flags byte. We parse the header,
 * look up the session by (local_ip, peer_ip, tunnel_id, session_id),
 * and dispatch:
 *
 *   DECAP_IP:  strip L2TP + PPP-proto bytes, set RX sw_if_index to the
 *              session's vnet interface, and forward to ip4-input or
 *              ip6-input based on the PPP protocol field.
 *
 *   DECAP_RAW: strip L2TP only (PPP frame intact), stash
 *              session->raw_opaque in vnet_buffer_l2tpv2_opaque, and
 *              forward to the runtime-resolved next-arc cached on the
 *              session. RAW is the LAC bridge path; LNS uses IP mode.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <l2tpv2/l2tpv2.h>

/* osvbng_punt protocol enum value for L2TP punt. Inlined here rather
 * than including <osvbng_punt/osvbng_punt.h> to keep this plugin free
 * of any cross-plugin header / link dependency — l2tpv2 reaches punt
 * only through the named graph-node arc `osvbng-punt-shm-tx`. The
 * enum value must stay in sync with osvbng_punt_protocol_t in the
 * punt plugin's header (kept stable by code review).
 *
 * Slot for the protocol on the buffer matches osvbng_punt.h:
 *   vnet_buffer_punt_protocol(b) := (b)->opaque2[1] */
#define OSVBNG_PUNT_PROTO_L2TP_LOCAL  6
#define vnet_buffer_punt_protocol(b)  ((b)->opaque2[1])

/* l2m->punt_shm_tx_next_arc is resolved once on the main thread at
 * plugin init (l2tpv2.c). vlib_node_add_next requires thread 0. */

#define PPP_PROTOCOL_IP4 0x0021
#define PPP_PROTOCOL_IP6 0x0057

#define L2TP_FLAG_BYTE_T (1 << 7)
#define L2TP_FLAG_BYTE_L (1 << 6)
#define L2TP_FLAG_BYTE_S (1 << 3)
#define L2TP_FLAG_BYTE_O (1 << 1)

typedef struct
{
  u32 next_index;
  u32 session_index;
  u16 local_tunnel_id;
  u16 local_session_id;
  u16 ppp_proto;
  u32 error;
} l2tpv2_input_trace_t;

static u8 *
format_l2tpv2_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2tpv2_input_trace_t *t = va_arg (*args, l2tpv2_input_trace_t *);

  s = format (s,
	      "l2tpv2-input tunnel_id %d session_id %d session_index %d "
	      "ppp_proto 0x%04x next %d error %d",
	      t->local_tunnel_id, t->local_session_id, t->session_index,
	      t->ppp_proto, t->next_index, t->error);
  return s;
}

/* Compute L2TPv2 header length from the flags byte. */
static_always_inline u32
l2tpv2_header_len (const u8 *p)
{
  u32 len = 6;
  u8 flags = p[0];
  if (flags & L2TP_FLAG_BYTE_L)
    len += 2;
  if (flags & L2TP_FLAG_BYTE_S)
    len += 4;
  if (flags & L2TP_FLAG_BYTE_O)
    {
      u16 off = clib_net_to_host_u16 (*(u16 *) (p + len));
      len += 2 + off;
    }
  return len;
}

VLIB_NODE_FN (l2tpv2_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  l2tpv2_main_t *l2m = &l2tpv2_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_decapsulated = 0;
  u32 pkts_no_session = 0;
  u32 pkts_truncated = 0;
  u32 pkts_unknown_proto = 0;

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
	  u32 next0 = L2TPV2_INPUT_NEXT_DROP;
	  u32 error0 = 0;
	  u32 session_index = ~0;
	  u16 local_tunnel_id = 0, local_session_id = 0, ppp_proto = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  if (PREDICT_FALSE (b0->current_length < 6))
	    {
	      error0 = L2TPV2_ERROR_TRUNCATED;
	      pkts_truncated++;
	      goto trace00;
	    }

	  u8 *hdr = vlib_buffer_get_current (b0);

	  if (PREDICT_FALSE (hdr[0] & L2TP_FLAG_BYTE_T))
	    {
	      /* Control packet (T=1): SCCRQ/SCCRP/SCCCN/ICRQ/ICRP/ICCN/
	       * StopCCN/HELLO/ZLB. Punt the full Ethernet frame to the
	       * Go control plane via the SHM service. Mirrors the
	       * non-IP-PPP punt path below — same proto tag, same rewind. */
	      i16 rewind = sizeof (udp_header_t)
			   + sizeof (ip4_header_t)
			   + sizeof (ethernet_header_t);
	      if (b0->flags & VNET_BUFFER_F_VLAN_2_DEEP)
		rewind += 2 * sizeof (ethernet_vlan_header_t);
	      else if (b0->flags & VNET_BUFFER_F_VLAN_1_DEEP)
		rewind += sizeof (ethernet_vlan_header_t);
	      vlib_buffer_advance (b0, -rewind);

	      if (PREDICT_FALSE (l2m->punt_shm_tx_next_arc == ~0u))
		{
		  next0 = L2TPV2_INPUT_NEXT_DROP;
		}
	      else
		{
		  vnet_buffer_punt_protocol (b0) = OSVBNG_PUNT_PROTO_L2TP_LOCAL;
		  next0 = l2m->punt_shm_tx_next_arc;
		}
	      goto trace00;
	    }

	  u8 version = hdr[1] & 0x0f;
	  if (PREDICT_FALSE (version != 2))
	    {
	      error0 = L2TPV2_ERROR_UNKNOWN_PROTOCOL;
	      goto trace00;
	    }

	  u32 l2tp_len = l2tpv2_header_len (hdr);
	  if (PREDICT_FALSE (b0->current_length < l2tp_len + 2))
	    {
	      error0 = L2TPV2_ERROR_TRUNCATED;
	      pkts_truncated++;
	      goto trace00;
	    }

	  u32 idoff = 2 + ((hdr[0] & L2TP_FLAG_BYTE_L) ? 2 : 0);
	  local_tunnel_id =
	    clib_net_to_host_u16 (*(u16 *) (hdr + idoff));
	  local_session_id =
	    clib_net_to_host_u16 (*(u16 *) (hdr + idoff + 2));

	  /* Recover the local + peer IPs from the IP4 header that lives
	   * (ip4_header_len + udp_header_len) bytes behind our current
	   * position — UDP demux walked us past those. */
	  ip4_header_t *ip4 = (ip4_header_t *)
	    ((u8 *) hdr -
	     (sizeof (udp_header_t) + sizeof (ip4_header_t)));

	  l2tpv2_session_key_t key;
	  l2tpv2_session_key_set (&key, &ip4->dst_address, &ip4->src_address,
				  local_tunnel_id, local_session_id);
	  clib_bihash_kv_16_8_t kv = {
	    .key = { key.as_u64[0], key.as_u64[1] },
	  };
	  if (PREDICT_FALSE (
		clib_bihash_search_inline_16_8 (&l2m->session_table, &kv) != 0))
	    {
	      error0 = L2TPV2_ERROR_NO_SUCH_SESSION;
	      pkts_no_session++;
	      goto trace00;
	    }
	  session_index = (u32) kv.value;
	  l2tpv2_session_t *s =
	    pool_elt_at_index (l2m->sessions, session_index);

	  ppp_proto = clib_net_to_host_u16 (*(u16 *) (hdr + l2tp_len));

	  if (s->decap_mode == L2TPV2_DECAP_IP)
	    {
	      switch (ppp_proto)
		{
		case PPP_PROTOCOL_IP4:
		  vlib_buffer_advance (b0, l2tp_len + 2);
		  vnet_buffer (b0)->sw_if_index[VLIB_RX] = s->sw_if_index;
		  next0 = L2TPV2_INPUT_NEXT_IP4_INPUT;
		  pkts_decapsulated++;
		  break;
		case PPP_PROTOCOL_IP6:
		  vlib_buffer_advance (b0, l2tp_len + 2);
		  vnet_buffer (b0)->sw_if_index[VLIB_RX] = s->sw_if_index;
		  next0 = L2TPV2_INPUT_NEXT_IP6_INPUT;
		  pkts_decapsulated++;
		  break;
		default:
		  /* Non-IP PPP (LCP, CHAP, IPCP, IPv6CP, Echo, ...) is
		   * control plane work — punt the full L2 frame back to
		   * userspace via the existing L2TP punt channel. Rewind
		   * to the Ethernet header so the SHM consumer parses the
		   * same datagram shape that the punt plugin produces for
		   * control (T=1) messages. */
		  {
		    i16 rewind = sizeof (udp_header_t)
				 + sizeof (ip4_header_t)
				 + sizeof (ethernet_header_t);
		    if (b0->flags & VNET_BUFFER_F_VLAN_2_DEEP)
		      rewind += 2 * sizeof (ethernet_vlan_header_t);
		    else if (b0->flags & VNET_BUFFER_F_VLAN_1_DEEP)
		      rewind += sizeof (ethernet_vlan_header_t);
		    vlib_buffer_advance (b0, -rewind);

		    /* Hand off to the punt plugin's shared SHM service via
		     * its public graph node. No cross-plugin function call;
		     * arc resolved by name at first frame. */
		    if (PREDICT_FALSE (l2m->punt_shm_tx_next_arc == ~0u))
		      {
			next0 = L2TPV2_INPUT_NEXT_DROP;
		      }
		    else
		      {
			vnet_buffer_punt_protocol (b0) =
			  OSVBNG_PUNT_PROTO_L2TP_LOCAL;
			next0 = l2m->punt_shm_tx_next_arc;
		      }
		    pkts_decapsulated++;
		  }
		  break;
		}
	    }
	  else
	    {
	      vlib_buffer_advance (b0, l2tp_len);
	      vnet_buffer_l2tpv2_opaque (b0) = s->raw_opaque;
	      if (PREDICT_FALSE (s->raw_next_arc == ~0u))
		{
		  error0 = L2TPV2_ERROR_NO_SUCH_SESSION;
		  goto trace00;
		}
	      /* Use the pre-resolved arc from session-create. Calling
	       * vlib_node_add_next from the data path is a thread-safety
	       * violation (it mutates node graph and asserts off main
	       * thread). */
	      next0 = s->raw_next_arc;
	      pkts_decapsulated++;
	    }

	trace00:
	  b0->error = error0 ? node->errors[error0] : 0;
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2tpv2_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->session_index = session_index;
	      tr->local_tunnel_id = local_tunnel_id;
	      tr->local_session_id = local_session_id;
	      tr->ppp_proto = ppp_proto;
	      tr->error = error0;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, l2tpv2_input_node.index,
			       L2TPV2_ERROR_DECAPSULATED, pkts_decapsulated);
  vlib_node_increment_counter (vm, l2tpv2_input_node.index,
			       L2TPV2_ERROR_NO_SUCH_SESSION, pkts_no_session);
  vlib_node_increment_counter (vm, l2tpv2_input_node.index,
			       L2TPV2_ERROR_TRUNCATED, pkts_truncated);
  vlib_node_increment_counter (vm, l2tpv2_input_node.index,
			       L2TPV2_ERROR_UNKNOWN_PROTOCOL,
			       pkts_unknown_proto);

  return from_frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
char *l2tpv2_error_strings[] = {
#define l2tpv2_error(n, s) s,
#include <l2tpv2/l2tpv2_error.def>
#undef l2tpv2_error
};
#endif /* CLIB_MARCH_VARIANT */

VLIB_REGISTER_NODE (l2tpv2_input_node) = {
  .name = "l2tpv2-input",
  .vector_size = sizeof (u32),
  .n_errors = L2TPV2_N_ERROR,
  .error_strings = l2tpv2_error_strings,
  .n_next_nodes = L2TPV2_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [L2TPV2_INPUT_NEXT_##s] = n,
    foreach_l2tpv2_input_next
#undef _
  },
  .format_trace = format_l2tpv2_input_trace,
};
