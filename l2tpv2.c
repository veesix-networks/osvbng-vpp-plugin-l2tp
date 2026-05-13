/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * L2TPv2 Plugin (RFC 2661) — main file.
 *
 * Plugin registration, init, formatting, CLI, and the vnet interface
 * machinery needed by DECAP_IP sessions to present per-session interfaces
 * to FIB / counters. Tunnel and session bookkeeping lives in
 * l2tpv2_session.c; data ingress in l2tpv2_input.c; encap
 * support in l2tpv2_output.c; binapi handlers in
 * l2tpv2_api.c.
 */

#include <stdint.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/log.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_table.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/udp/udp.h>

#include <l2tpv2/l2tpv2.h>

#include <vppinfra/hash.h>
#include <vppinfra/bihash_template.c>

l2tpv2_main_t l2tpv2_main;

extern u8 *l2tpv2_build_rewrite (vnet_main_t *vnm, u32 sw_if_index,
					vnet_link_t link_type,
					const void *dst_address);
extern void l2tpv2_fixup (vlib_main_t *vm, const ip_adjacency_t *adj,
				 vlib_buffer_t *b0, const void *data);

u8 *
format_l2tpv2_tunnel (u8 *s, va_list *args)
{
  l2tpv2_tunnel_t *t = va_arg (*args, l2tpv2_tunnel_t *);
  l2tpv2_main_t *l2m = &l2tpv2_main;

  s = format (s, "[%d] %U:%d <-> %U:%d local-id %d peer-id %d df %d ref %d",
	      t - l2m->tunnels, format_ip4_address, &t->local_ip,
	      t->local_udp_port, format_ip4_address, &t->peer_ip,
	      t->peer_udp_port, t->local_tunnel_id, t->peer_tunnel_id,
	      t->df_bit, t->ref_count);
  return s;
}

u8 *
format_l2tpv2_session (u8 *s, va_list *args)
{
  l2tpv2_session_t *sess = va_arg (*args, l2tpv2_session_t *);
  l2tpv2_main_t *l2m = &l2tpv2_main;

  s = format (s, "[%d] tunnel %d local-sid %d peer-sid %d mode %s",
	      sess - l2m->sessions, sess->tunnel_index, sess->local_session_id,
	      sess->peer_session_id,
	      sess->decap_mode == L2TPV2_DECAP_IP ? "ip" : "raw");
  if (sess->decap_mode == L2TPV2_DECAP_IP)
    s = format (s, " sw-if-index %d encap-if-index %d decap-fib-index %d",
		sess->sw_if_index, sess->encap_if_index, sess->decap_fib_index);
  else
    s = format (s, " next-node %d opaque 0x%08x encap-if-index %d",
		sess->raw_next_node_index, sess->raw_opaque, sess->encap_if_index);
  return s;
}

static u8 *
format_l2tpv2_if_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "l2tpv2_session%d", dev_instance);
}

static clib_error_t *
l2tpv2_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
		   ? VNET_HW_INTERFACE_FLAG_LINK_UP
		   : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

VNET_DEVICE_CLASS (l2tpv2_device_class) = {
  .name = "L2TPv2",
  .format_device_name = format_l2tpv2_if_name,
  .admin_up_down_function = l2tpv2_interface_admin_up_down,
};

static u8 *
format_l2tpv2_header_with_length (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

/* Update the midchain adjacency for a session. The rewrite (IP+UDP+
 * L2TPv2) is built once; the adjacency stacks on either:
 *   - a per-session forced egress interface (when encap_if_index is
 *     set, mirroring PPPoE's interface_tx_dpo pattern), OR
 *   - the FIB-resolved DPO for the tunnel's peer IP (when
 *     encap_if_index is ~0). This is the loopback / routed-peer case.
 *
 * For the FIB path we contribute forwarding once at session-add; if
 * the route to the peer changes during the session's lifetime the
 * midchain still points at the old path. Tunnels created after the
 * route change pick up the new path. Full back-walk restacking is
 * deferred until a tunnel-level fib_node registration lands. */
static void
l2tpv2_update_adj (vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai)
{
  l2tpv2_main_t *l2m = &l2tpv2_main;
  l2tpv2_session_t *sess;
  l2tpv2_tunnel_t *tunnel;
  ip_adjacency_t *adj;
  dpo_id_t dpo = DPO_INVALID;
  u32 session_index;

  ASSERT (ADJ_INDEX_INVALID != ai);

  adj = adj_get (ai);
  session_index = l2m->session_index_by_sw_if_index[sw_if_index];
  sess = pool_elt_at_index (l2m->sessions, session_index);
  tunnel = pool_elt_at_index (l2m->tunnels, sess->tunnel_index);

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_GLEAN:
    case IP_LOOKUP_NEXT_BCAST:
      adj_nbr_midchain_update_rewrite (
	ai, l2tpv2_fixup, NULL, ADJ_FLAG_NONE,
	l2tpv2_build_rewrite (vnm, sw_if_index, adj->ia_link, NULL));
      break;
    case IP_LOOKUP_NEXT_MCAST:
      adj_mcast_midchain_update_rewrite (
	ai, l2tpv2_fixup, NULL, ADJ_FLAG_NONE,
	l2tpv2_build_rewrite (vnm, sw_if_index, adj->ia_link, NULL), 0,
	0);
      break;
    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_MIDCHAIN:
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
      ASSERT (0);
      break;
    }

  if (sess->encap_if_index != ~0u)
    {
      interface_tx_dpo_add_or_lock (vnet_link_to_dpo_proto (adj->ia_link),
				    sess->encap_if_index, &dpo);
    }
  else
    {
      fib_prefix_t pfx = {
	.fp_proto = FIB_PROTOCOL_IP4,
	.fp_len = 32,
      };
      pfx.fp_addr.ip4.as_u32 = tunnel->peer_ip.as_u32;
      fib_node_index_t fei =
	fib_table_lookup (tunnel->encap_fib_index, &pfx);
      if (fei == FIB_NODE_INDEX_INVALID)
	{
	  /* No route to peer; leave the midchain unstacked. Packets
	   * destined to the session will drop until the operator
	   * installs a route. */
	  return;
	}
      fib_entry_contribute_forwarding (
	fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, &dpo);
    }
  adj_nbr_midchain_stack (ai, &dpo);
  dpo_reset (&dpo);
}

VNET_HW_INTERFACE_CLASS (l2tpv2_hw_class) = {
  .name = "L2TPv2",
  .format_header = format_l2tpv2_header_with_length,
  .build_rewrite = l2tpv2_build_rewrite,
  .update_adjacency = l2tpv2_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

/*
 * CLI: create l2tpv2 tunnel
 */
static clib_error_t *
create_l2tpv2_tunnel_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  ip4_address_t local_ip = { 0 };
  ip4_address_t peer_ip = { 0 };
  u32 local_tid = 0, peer_tid = 0;
  u32 local_port = L2TPV2_UDP_PORT, peer_port = L2TPV2_UDP_PORT;
  u8 is_add = 1;
  u8 df_bit = 0;
  u8 local_ip_set = 0, peer_ip_set = 0;
  vnet_l2tpv2_add_del_tunnel_args_t a = { 0 };
  u32 tunnel_index = ~0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "local-ip %U", unformat_ip4_address,
			 &local_ip))
	local_ip_set = 1;
      else if (unformat (line_input, "peer-ip %U", unformat_ip4_address,
			 &peer_ip))
	peer_ip_set = 1;
      else if (unformat (line_input, "local-id %d", &local_tid))
	;
      else if (unformat (line_input, "peer-id %d", &peer_tid))
	;
      else if (unformat (line_input, "local-port %d", &local_port))
	;
      else if (unformat (line_input, "peer-port %d", &peer_port))
	;
      else if (unformat (line_input, "df"))
	df_bit = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!local_ip_set || !peer_ip_set)
    {
      error = clib_error_return (0, "local-ip and peer-ip required");
      goto done;
    }
  if (local_tid == 0 || local_tid > 0xffff)
    {
      error = clib_error_return (0, "local-id must be 1..65535");
      goto done;
    }
  if (is_add && (peer_tid == 0 || peer_tid > 0xffff))
    {
      error = clib_error_return (0, "peer-id must be 1..65535 when adding");
      goto done;
    }

  a.is_add = is_add;
  a.local_ip.as_u32 = local_ip.as_u32;
  a.peer_ip.as_u32 = peer_ip.as_u32;
  a.local_tunnel_id = (u16) local_tid;
  a.peer_tunnel_id = (u16) peer_tid;
  a.local_udp_port = (u16) local_port;
  a.peer_udp_port = (u16) peer_port;
  a.df_bit = df_bit;

  rv = vnet_l2tpv2_add_del_tunnel (&a, &tunnel_index);
  switch (rv)
    {
    case 0:
      if (is_add)
	vlib_cli_output (vm, "tunnel-index %u", tunnel_index);
      break;
    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "tunnel already exists");
      break;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "tunnel does not exist");
      break;
    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "tunnel has active sessions; cannot delete");
      break;
    default:
      error = clib_error_return (0, "add_del_tunnel returned %d", rv);
      break;
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (create_l2tpv2_tunnel_command, static) = {
  .path = "create l2tpv2 tunnel",
  .short_help =
    "create l2tpv2 tunnel local-ip <ip> peer-ip <ip> local-id <n>"
    " peer-id <n> [local-port <n>] [peer-port <n>] [df] [del]",
  .function = create_l2tpv2_tunnel_command_fn,
};

/*
 * CLI: create l2tpv2 session
 */
static clib_error_t *
create_l2tpv2_session_command_fn (vlib_main_t *vm,
				       unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  l2tpv2_main_t *l2m = &l2tpv2_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  ip4_address_t local_ip = { 0 };
  ip4_address_t peer_ip = { 0 };
  u32 local_tid = 0, local_sid = 0, peer_sid = 0;
  u32 decap_vrf = 0;
  u32 encap_if_index = ~0;
  u32 raw_opaque = 0;
  u8 *raw_node_name = 0;
  u8 mode = L2TPV2_DECAP_IP;
  u8 is_add = 1;
  u8 local_ip_set = 0, peer_ip_set = 0;
  vnet_l2tpv2_add_del_session_args_t a = { 0 };
  u32 sw_if_index = ~0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "local-ip %U", unformat_ip4_address,
			 &local_ip))
	local_ip_set = 1;
      else if (unformat (line_input, "peer-ip %U", unformat_ip4_address,
			 &peer_ip))
	peer_ip_set = 1;
      else if (unformat (line_input, "local-tid %d", &local_tid))
	;
      else if (unformat (line_input, "local-sid %d", &local_sid))
	;
      else if (unformat (line_input, "peer-sid %d", &peer_sid))
	;
      else if (unformat (line_input, "mode ip"))
	mode = L2TPV2_DECAP_IP;
      else if (unformat (line_input, "mode raw"))
	mode = L2TPV2_DECAP_RAW;
      else if (unformat (line_input, "decap-vrf-id %d", &decap_vrf))
	;
      else if (unformat (line_input, "encap-if-index %d", &encap_if_index))
	;
      else if (unformat (line_input, "encap-if %U", unformat_vnet_sw_interface,
			 l2m->vnet_main, &encap_if_index))
	;
      else if (unformat (line_input, "raw-next-node %s", &raw_node_name))
	;
      else if (unformat (line_input, "raw-opaque %x", &raw_opaque))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!local_ip_set || !peer_ip_set)
    {
      error = clib_error_return (0, "local-ip and peer-ip required");
      goto done;
    }
  if (local_tid == 0 || local_tid > 0xffff)
    {
      error = clib_error_return (0, "local-tid must be 1..65535");
      goto done;
    }
  if (is_add && (local_sid == 0 || local_sid > 0xffff))
    {
      error = clib_error_return (0, "local-sid must be 1..65535 when adding");
      goto done;
    }
  if (is_add && encap_if_index == ~0)
    {
      error = clib_error_return (0, "encap-if required when adding");
      goto done;
    }
  if (is_add && mode == L2TPV2_DECAP_RAW && raw_node_name == 0)
    {
      error =
	clib_error_return (0, "raw-next-node required when mode is raw");
      goto done;
    }

  a.is_add = is_add;
  a.local_ip.as_u32 = local_ip.as_u32;
  a.peer_ip.as_u32 = peer_ip.as_u32;
  a.local_tunnel_id = (u16) local_tid;
  a.local_session_id = (u16) local_sid;
  a.peer_session_id = (u16) peer_sid;
  a.decap_mode = mode;
  a.decap_vrf_id = decap_vrf;
  a.encap_if_index = encap_if_index;
  a.raw_next_node_name = (const char *) raw_node_name;
  a.raw_opaque = raw_opaque;

  rv = vnet_l2tpv2_add_del_session (&a, &sw_if_index);
  switch (rv)
    {
    case 0:
      if (is_add && mode == L2TPV2_DECAP_IP)
	vlib_cli_output (vm, "%U", format_vnet_sw_if_index_name,
			 vnet_get_main (), sw_if_index);
      else if (is_add)
	vlib_cli_output (vm, "session added");
      break;
    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "session already exists");
      break;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      /* Same code is returned for "owning tunnel missing" on add and
       * "session not found" on delete; distinguish by `is_add`. */
      if (is_add)
	error = clib_error_return (0, "owning tunnel does not exist");
      else
	error = clib_error_return (0, "session does not exist");
      break;
    case VNET_API_ERROR_NO_SUCH_FIB:
      error = clib_error_return (0, "no such decap VRF");
      break;
    case VNET_API_ERROR_NO_SUCH_NODE:
      error = clib_error_return (0, "raw-next-node not found in graph");
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "invalid mode or missing argument");
      break;
    default:
      error = clib_error_return (0, "add_del_session returned %d", rv);
      break;
    }

done:
  vec_free (raw_node_name);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (create_l2tpv2_session_command, static) = {
  .path = "create l2tpv2 session",
  .short_help =
    "create l2tpv2 session local-ip <ip> peer-ip <ip>"
    " local-tid <n> local-sid <n> peer-sid <n>"
    " mode (ip|raw) [decap-vrf-id <n>] encap-if <intfc>"
    " [raw-next-node <name>] [raw-opaque <hex>] [del]",
  .function = create_l2tpv2_session_command_fn,
};

/*
 * CLI: show l2tpv2 tunnel / session
 */
static clib_error_t *
show_l2tpv2_tunnel_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  l2tpv2_main_t *l2m = &l2tpv2_main;
  l2tpv2_tunnel_t *t;

  if (pool_elts (l2m->tunnels) == 0)
    {
      vlib_cli_output (vm, "no l2tp tunnels configured");
      return 0;
    }

  pool_foreach (t, l2m->tunnels)
    {
      vlib_cli_output (vm, "%U", format_l2tpv2_tunnel, t);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_l2tpv2_tunnel_command, static) = {
  .path = "show l2tpv2 tunnel",
  .short_help = "show l2tpv2 tunnel",
  .function = show_l2tpv2_tunnel_command_fn,
};

static clib_error_t *
show_l2tpv2_session_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  l2tpv2_main_t *l2m = &l2tpv2_main;
  l2tpv2_session_t *s;

  if (pool_elts (l2m->sessions) == 0)
    {
      vlib_cli_output (vm, "no l2tp sessions configured");
      return 0;
    }

  pool_foreach (s, l2m->sessions)
    {
      vlib_cli_output (vm, "%U", format_l2tpv2_session, s);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_l2tpv2_session_command, static) = {
  .path = "show l2tpv2 session",
  .short_help = "show l2tpv2 session",
  .function = show_l2tpv2_session_command_fn,
};

clib_error_t *
l2tpv2_init (vlib_main_t *vm)
{
  l2tpv2_main_t *l2m = &l2tpv2_main;

  l2m->log_class = vlib_log_register_class ("l2tpv2", 0);
  vlib_log_info (l2m->log_class, "initializing");

  l2m->vlib_main = vm;
  l2m->vnet_main = vnet_get_main ();
  l2m->punt_shm_tx_next_arc = ~0;

  /* Resolve the osvbng-punt-shm-tx next-arc on the main thread now;
   * vlib_node_add_next asserts thread-0. Cached for worker threads
   * to dispatch T=1 control frames into the SHM service node. ~0
   * means the punt plugin is not loaded and control frames drop. */
  {
    vlib_node_t *target = vlib_get_node_by_name (vm,
						 (u8 *) "osvbng-punt-shm-tx");
    if (target)
      l2m->punt_shm_tx_next_arc =
	vlib_node_add_next (vm, l2tpv2_input_node.index, target->index);
  }

  clib_bihash_init_16_8 (&l2m->session_table, "l2tpv2 session table",
			 L2TPV2_SESSION_NUM_BUCKETS,
			 L2TPV2_SESSION_MEMORY_SIZE);
  clib_bihash_init_16_8 (&l2m->tunnel_table, "l2tpv2 tunnel table",
			 L2TPV2_TUNNEL_NUM_BUCKETS,
			 L2TPV2_TUNNEL_MEMORY_SIZE);

  /* Claim UDP/1701 in the IPv4 input path. Without this, L2TP packets
   * fall through to ip4-punt-redirect → the linux-cp tap, never
   * reaching this plugin. Mirrors the upstream l2tpv3 plugin's
   * ip6_register_protocol(IP_PROTOCOL_L2TP, ...) pattern. */
  udp_register_dst_port (vm, L2TPV2_UDP_PORT, l2tpv2_input_node.index,
			 1 /* is_ip4 */);

  vlib_log_notice (l2m->log_class, "initialized successfully");
  return 0;
}

VLIB_INIT_FUNCTION (l2tpv2_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "L2TPv2 Plugin (RFC 2661)",
};
