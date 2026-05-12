/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * L2TPv2 data input graph node.
 *
 * This node is the destination of the T=0 (data) arc from the punt plugin's
 * UDP/1701 owner. Phase 1 skeleton: every packet is counted and dropped.
 * Phase 2+ replaces the body with the bihash session lookup, header strip,
 * and role dispatch described in IMPLEMENTATION_SPEC.md §"High-level
 * architecture".
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <l2tpv2/l2tpv2.h>

typedef struct
{
  u32 next_index;
  u32 session_index;
  u16 local_tunnel_id;
  u16 local_session_id;
  u32 error;
} l2tpv2_input_trace_t;

static u8 *
format_l2tpv2_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2tpv2_input_trace_t *t = va_arg (*args, l2tpv2_input_trace_t *);

  s = format (s, "l2tpv2-input tunnel_id %d session_id %d session_index %d next %d error %d",
	      t->local_tunnel_id, t->local_session_id, t->session_index,
	      t->next_index, t->error);
  return s;
}

VLIB_NODE_FN (l2tpv2_input_node) (vlib_main_t *vm,
					 vlib_node_runtime_t *node,
					 vlib_frame_t *from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
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
	  u32 next0 = L2TPV2_INPUT_NEXT_DROP;
	  u32 error0 = L2TPV2_ERROR_NO_SUCH_SESSION;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  pkts_dropped++;

	  b0->error = node->errors[error0];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2tpv2_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->error = error0;
	      tr->session_index = ~0;
	      tr->local_tunnel_id = 0;
	      tr->local_session_id = 0;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, l2tpv2_input_node.index,
			       L2TPV2_ERROR_NO_SUCH_SESSION,
			       pkts_dropped);

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
