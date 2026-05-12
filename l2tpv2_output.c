/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * L2TPv2 egress encap support.
 *
 * Phase 1 skeleton: build_rewrite returns a minimal placeholder rewrite
 * and the fixup is a no-op. Phase 5 replaces these with the full
 * Eth+IP+UDP+L2TP+PPP rewrite + length fixup per RFC 2661 §4.4 (mirrors
 * the pppoe_build_rewrite / pppoe_fixup pattern but with L2TP/UDP framing
 * instead of PPPoE).
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_midchain.h>
#include <l2tpv2/l2tpv2.h>

/* Phase 1: empty rewrite. Lets adjacency programming succeed for IP-mode
 * sessions without doing real encap. Real Eth+IP+UDP+L2TP+PPP rewrite is
 * added in Phase 5. */
u8 *
l2tpv2_build_rewrite (vnet_main_t *vnm, u32 sw_if_index,
			     vnet_link_t link_type, const void *dst_address)
{
  u8 *rw = 0;
  return rw;
}

void
l2tpv2_fixup (vlib_main_t *vm, const ip_adjacency_t *adj,
		     vlib_buffer_t *b0, const void *data)
{
  /* Phase 1: no-op. Phase 5: fill in L2TP length field per RFC 2661 §3.1. */
}
