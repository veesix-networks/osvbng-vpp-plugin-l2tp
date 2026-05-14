/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * L2TPv2 Plugin
 *
 * A pure L2TPv2 (RFC 2661) dataplane plugin for VPP. The plugin owns:
 *   - UDP/1701 demux (T-bit dispatched here by the punt plugin)
 *   - Per-tunnel and per-session lookup tables (bihash)
 *   - L2TP+UDP+IP encap (midchain on a vnet interface for IP mode, or
 *     raw output for forward-mode sessions)
 *   - L2TP decap to either IP mode (strip L2TP+PPP, dispatch to ip4/ip6
 *     input with RX sw_if_index set) or raw mode (strip L2TP only, hand
 *     the PPP frame to a caller-specified graph next-node).
 *
 * Decap modes are deliberately generic so this plugin can be consumed
 * outside of osvbng. PPPoE bridging for LAC use cases lives entirely in
 * the PPPoE plugin and a dedicated bridge node — this plugin never
 * touches PPPoE headers, MAC addresses, or VLAN tags.
 */

#ifndef __included_l2tpv2_h__
#define __included_l2tpv2_h__

#include <vnet/plugin/plugin.h>
#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_node.h>
#include <vnet/fib/fib_entry_track.h>
#include <vlib/vlib.h>
#include <vppinfra/bihash_16_8.h>

/* L2TPv2 well-known UDP port (RFC 2661 §3) */
#define L2TPV2_UDP_PORT 1701

/* L2TPv2 header version field (low nibble of first byte) */
#define L2TPV2_VERSION 2
#define L2TPV3_VERSION 3

/* L2TPv2 header flag bits (high byte of first 16 bits) */
#define L2TP_FLAG_T (1 << 15)	/* Message type: 1 = control, 0 = data */
#define L2TP_FLAG_L (1 << 14)	/* Length field present */
#define L2TP_FLAG_S (1 << 11)	/* Ns/Nr present (sequence) */
#define L2TP_FLAG_O (1 << 9)	/* Offset Size present */
#define L2TP_FLAG_P (1 << 8)	/* Priority */

/* Decap modes. See file header. */
typedef enum
{
  /* Strip L2TP+PPP framing; dispatch to ip4-input or ip6-input based on
   * the PPP protocol field. RX sw_if_index is set to the session's vnet
   * interface so FIB lookup happens in the right VRF and per-session
   * counters work. Use this for L2TPv2 endpoints that terminate PPP
   * locally (e.g. LNS). */
  L2TPV2_DECAP_IP = 0,

  /* Strip L2TP only; hand the PPP frame to `raw_next_node_index` with
   * `raw_opaque` stashed in vnet_buffer2(b)->l2tpv2.opaque so the
   * downstream node can correlate to its own session state. Use this
   * for L2TPv2 endpoints that do not terminate PPP themselves (e.g. a
   * LAC bridging to PPPoE). */
  L2TPV2_DECAP_RAW = 1,
} l2tpv2_decap_mode_t;

/* Errors */
typedef enum
{
#define l2tpv2_error(n, s) L2TPV2_ERROR_##n,
#include <l2tpv2/l2tpv2_error.def>
#undef l2tpv2_error
  L2TPV2_N_ERROR,
} l2tpv2_error_t;

extern char *l2tpv2_error_strings[];

/* Per-tunnel state. Control-channel state (Ns/Nr, retransmit queue,
 * slow-start window) lives in the userspace control plane; the dataplane
 * only needs addressing and IDs to build outgoing packets. */
typedef struct l2tpv2_tunnel_t_ l2tpv2_tunnel_t;

struct l2tpv2_tunnel_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Embedded FIB node so the tunnel can register for forwarding-state
   * back-walks on the peer IP (loopback / routed peers). The fib_node
   * field is owned by VPP's FIB machinery; do not move it. */
  fib_node_t node;

  /* Endpoint addresses (IPv4 only in v1). */
  ip4_address_t local_ip;
  ip4_address_t peer_ip;

  /* IDs in HOST byte order.
   *   local_tunnel_id = the ID we assigned (peer puts this on packets to us)
   *   peer_tunnel_id  = the ID peer assigned us (we put this on packets to peer) */
  u16 local_tunnel_id;
  u16 peer_tunnel_id;

  /* UDP ports in HOST byte order. */
  u16 local_udp_port;
  u16 peer_udp_port;

  /* Egress IP DF bit (RFC 2661 §4.4.5 recommends DF=0). */
  u8 df_bit;

  /* FIB tracking for the peer IP. Allocated at first session add;
   * released at last session del. The midchain adjacency restacks on
   * this entry's contributed DPO whenever the peer's forwarding state
   * changes. */
  u32 encap_fib_index;
  fib_node_index_t fib_entry_index;
  u32 sibling_index;

  /* Number of sessions currently bound to this tunnel. */
  u32 ref_count;
};

/* Per-session state. */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Owning tunnel index (into l2tpv2_main_t.tunnels pool). */
  u32 tunnel_index;

  /* Session IDs in HOST byte order. */
  u16 local_session_id;
  u16 peer_session_id;

  /* Decap mode. See l2tpv2_decap_mode_t. */
  u8 decap_mode;

  /* DECAP_RAW: graph node index for raw PPP frame delivery. ~0 in IP mode. */
  u32 raw_next_node_index;

  /* DECAP_RAW: pre-resolved next-arc index from l2tpv2-input ->
   * raw_next_node_index. vlib_node_add_next() must run on the main
   * thread (it mutates the node graph); we resolve once at
   * session-create time and the data path reads this cached slot. */
  u32 raw_next_arc;

  /* DECAP_RAW: opaque u32 stashed in vnet_buffer2(b) for downstream
   * correlation (e.g. the partner PPPoE session sw_if_index). 0 in IP mode. */
  u32 raw_opaque;

  /* DECAP_IP: per-session vnet interface (presents IP to FIB and provides
   * counters). ~0 in raw mode. */
  u32 sw_if_index;
  u32 hw_if_index;

  /* DECAP_IP: FIB index for decapsulated traffic (resolved from VRF id
   * at session creation). 0 in raw mode. */
  u32 decap_fib_index;
  u32 decap_fib_index_ip6;

  /* TX interface for outbound L2TP encap packets. */
  u32 encap_if_index;

  /* Subscriber IPv4 bound on this session's per-session vnet interface.
   * DECAP_IP only. Tracked here so session-delete can run the unbind
   * before the per-session interface is torn down. */
  ip4_address_t client_ipv4;
  u8 ipv4_bound;

  /* Subscriber IPv6 (IA_NA) bound on this session. DECAP_IP only. */
  ip6_address_t client_ipv6;
  u8 ipv6_bound;

  /* Delegated prefix routed to this session, with next-hop used for
   * the FIB path. DECAP_IP only. */
  ip6_address_t delegated_prefix;
  u8 delegated_prefix_len;
  ip6_address_t pd_next_hop;

} l2tpv2_session_t;

#define foreach_l2tpv2_input_next                                       \
  _ (DROP, "error-drop")                                                       \
  _ (IP4_INPUT, "ip4-input")                                                   \
  _ (IP6_INPUT, "ip6-input")                                                   \
  _ (PUNT, "error-punt")

typedef enum
{
#define _(s, n) L2TPV2_INPUT_NEXT_##s,
  foreach_l2tpv2_input_next
#undef _
    L2TPV2_INPUT_N_NEXT,
} l2tpv2_input_next_t;

/* Session table sizing. Targets in IMPLEMENTATION_SPEC.md §15: 64k sessions
 * across 1k tunnels in v1. */
#define L2TPV2_SESSION_NUM_BUCKETS (64 * 1024)
#define L2TPV2_SESSION_MEMORY_SIZE (16 << 20)
#define L2TPV2_TUNNEL_NUM_BUCKETS (2 * 1024)
#define L2TPV2_TUNNEL_MEMORY_SIZE (4 << 20)

/* 16-byte bihash key for session lookup on incoming data packets.
 * Incoming packets carry the IDs we assigned (receiver-assigned semantics
 * per RFC 2661 §3.1). */
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t local_ip;
      ip4_address_t peer_ip;
      u16 local_tunnel_id;
      u16 local_session_id;
      u32 _pad;
    } fields;
    u64 as_u64[2];
  };
} l2tpv2_session_key_t;

STATIC_ASSERT_SIZEOF (l2tpv2_session_key_t, 16);

/* 16-byte bihash key for tunnel lookup. */
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t local_ip;
      ip4_address_t peer_ip;
      u16 local_tunnel_id;
      u16 _pad0;
      u32 _pad1;
    } fields;
    u64 as_u64[2];
  };
} l2tpv2_tunnel_key_t;

STATIC_ASSERT_SIZEOF (l2tpv2_tunnel_key_t, 16);

typedef struct
{
  /* FIB node type — registered at init so the tunnel back-walks
   * forwarding changes for the peer IP. */
  fib_node_type_t fib_node_type;

  /* Tunnel and session pools. */
  l2tpv2_tunnel_t *tunnels;
  l2tpv2_session_t *sessions;

  /* Lookup tables. */
  clib_bihash_16_8_t session_table;
  clib_bihash_16_8_t tunnel_table;

  /* Free vlib hw_if_indices for reuse (IP-mode sessions only). */
  u32 *free_session_hw_if_indices;

  /* sw_if_index -> session index. */
  u32 *session_index_by_sw_if_index;

  /* API message ID base. */
  u16 msg_id_base;

  /* Convenience. */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vlib_log_class_t log_class;

  /* Next-arc into osvbng-punt-shm-tx for T=1 control frames and post-
   * decap non-IP PPP frames. Resolved lazily on first use. ~0 means
   * the punt plugin is not loaded — control frames fall back to drop. */
  u32 punt_shm_tx_next_arc;

} l2tpv2_main_t;

extern l2tpv2_main_t l2tpv2_main;

extern vlib_node_registration_t l2tpv2_input_node;

/* FIB source used for subscriber routes on per-session DECAP_IP
 * interfaces. Allocated at plugin init in l2tpv2.c. */
extern fib_source_t l2tpv2_fib_src;

/* Tunnel add/del */
typedef struct
{
  u8 is_add;
  ip4_address_t local_ip;
  ip4_address_t peer_ip;
  u16 local_tunnel_id;
  u16 peer_tunnel_id;
  u16 local_udp_port;
  u16 peer_udp_port;
  u8 df_bit;
} vnet_l2tpv2_add_del_tunnel_args_t;

int vnet_l2tpv2_add_del_tunnel (
  vnet_l2tpv2_add_del_tunnel_args_t *a, u32 *tunnel_indexp);

/* Session add/del */
typedef struct
{
  u8 is_add;
  ip4_address_t local_ip;
  ip4_address_t peer_ip;
  u16 local_tunnel_id;
  u16 local_session_id;
  u16 peer_session_id;
  u8 decap_mode;

  /* DECAP_RAW: graph node name + opaque. */
  const char *raw_next_node_name;
  u32 raw_opaque;

  /* DECAP_IP: decap VRF. */
  u32 decap_vrf_id;

  /* Both modes: TX interface for outbound L2TP. */
  u32 encap_if_index;
} vnet_l2tpv2_add_del_session_args_t;

int vnet_l2tpv2_add_del_session (
  vnet_l2tpv2_add_del_session_args_t *a, u32 *sw_if_indexp);

/* Subscriber-side FIB binding on a DECAP_IP session. The plugin owns
 * the route lifecycle: routes get installed when is_add=1, removed
 * when is_add=0, and any leftover bindings are auto-cleaned on
 * session-delete so FIB entries never outlive the per-session vnet
 * interface. */
int vnet_l2tpv2_set_session_ipv4 (u32 sw_if_index, ip4_address_t *addr,
				  u8 is_add);
int vnet_l2tpv2_set_session_ipv6 (u32 sw_if_index, ip6_address_t *addr,
				  u8 is_add);
int vnet_l2tpv2_set_delegated_prefix (u32 sw_if_index, ip6_address_t *prefix,
				      u8 prefix_len, ip6_address_t *next_hop,
				      u8 is_add);

/* Cross-plugin buffer opaque used by L2TPv2's DECAP_RAW mode and by
 * upstream nodes (e.g. a PPPoE LAC bridge) that hand PPP frames into
 * `l2tpv2-output`. The slot carries a `u32` whose meaning is set by
 * the upstream node and consumed by the downstream node (typically a
 * session index in the consumer's own pool).
 *
 * Implementation note: piggy-backs on `vlib_buffer_t.opaque2[0]`.
 * If another plugin needs this slot, negotiate a dedicated slot in
 * VPP's vnet_buffer2 union rather than reusing this one. */
#define vnet_buffer_l2tpv2_opaque(b) ((b)->opaque2[0])

/* Build session key from incoming-packet header fields.
 * IDs passed in HOST byte order. */
static_always_inline void
l2tpv2_session_key_set (l2tpv2_session_key_t *k,
			       const ip4_address_t *local_ip,
			       const ip4_address_t *peer_ip,
			       u16 local_tunnel_id, u16 local_session_id)
{
  k->as_u64[0] = 0;
  k->as_u64[1] = 0;
  k->fields.local_ip.as_u32 = local_ip->as_u32;
  k->fields.peer_ip.as_u32 = peer_ip->as_u32;
  k->fields.local_tunnel_id = local_tunnel_id;
  k->fields.local_session_id = local_session_id;
}

static_always_inline void
l2tpv2_tunnel_key_set (l2tpv2_tunnel_key_t *k,
			      const ip4_address_t *local_ip,
			      const ip4_address_t *peer_ip,
			      u16 local_tunnel_id)
{
  k->as_u64[0] = 0;
  k->as_u64[1] = 0;
  k->fields.local_ip.as_u32 = local_ip->as_u32;
  k->fields.peer_ip.as_u32 = peer_ip->as_u32;
  k->fields.local_tunnel_id = local_tunnel_id;
}

#endif /* __included_l2tpv2_h__ */
