/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * L2TPv2 binapi handlers.
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>

#include <l2tpv2/l2tpv2.h>

#include <vnet/format_fns.h>
#include <l2tpv2/l2tpv2.api_enum.h>
#include <l2tpv2/l2tpv2.api_types.h>

#define REPLY_MSG_ID_BASE l2m->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_l2tpv2_add_del_tunnel_t_handler (
  vl_api_l2tpv2_add_del_tunnel_t *mp)
{
  vl_api_l2tpv2_add_del_tunnel_reply_t *rmp;
  l2tpv2_main_t *l2m = &l2tpv2_main;
  vnet_l2tpv2_add_del_tunnel_args_t a = { 0 };
  ip46_address_t local_ip, peer_ip;
  u32 tunnel_index = ~0;
  int rv = 0;

  ip_address_decode (&mp->local_ip, &local_ip);
  ip_address_decode (&mp->peer_ip, &peer_ip);

  if (!ip46_address_is_ip4 (&local_ip) || !ip46_address_is_ip4 (&peer_ip))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  a.is_add = mp->is_add;
  a.local_ip.as_u32 = local_ip.ip4.as_u32;
  a.peer_ip.as_u32 = peer_ip.ip4.as_u32;
  a.local_tunnel_id = ntohs (mp->local_tunnel_id);
  a.peer_tunnel_id = ntohs (mp->peer_tunnel_id);
  a.local_udp_port = ntohs (mp->local_udp_port);
  a.peer_udp_port = ntohs (mp->peer_udp_port);
  a.df_bit = mp->df_bit;

  rv = vnet_l2tpv2_add_del_tunnel (&a, &tunnel_index);

out:
  REPLY_MACRO2 (VL_API_L2TPV2_ADD_DEL_TUNNEL_REPLY,
		({ rmp->tunnel_index = htonl (tunnel_index); }));
}

static void
vl_api_l2tpv2_add_del_session_t_handler (
  vl_api_l2tpv2_add_del_session_t *mp)
{
  vl_api_l2tpv2_add_del_session_reply_t *rmp;
  l2tpv2_main_t *l2m = &l2tpv2_main;
  vnet_l2tpv2_add_del_session_args_t a = { 0 };
  ip46_address_t local_ip, peer_ip;
  u32 sw_if_index = ~0;
  int rv = 0;
  /* `string raw_next_node_name[64];` in the .api generates a bounded
   * fixed-size u8[64] byte array (not a vl_api_string_t), so we cast
   * the array directly — same pattern as upstream's l2tp plugin uses
   * for `string interface_name[64]` in `l2tp_api.c`. */
  const char *raw_name = (const char *) mp->raw_next_node_name;

  ip_address_decode (&mp->local_ip, &local_ip);
  ip_address_decode (&mp->peer_ip, &peer_ip);

  if (!ip46_address_is_ip4 (&local_ip) || !ip46_address_is_ip4 (&peer_ip))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  a.is_add = mp->is_add;
  a.local_ip.as_u32 = local_ip.ip4.as_u32;
  a.peer_ip.as_u32 = peer_ip.ip4.as_u32;
  a.local_tunnel_id = ntohs (mp->local_tunnel_id);
  a.local_session_id = ntohs (mp->local_session_id);
  a.peer_session_id = ntohs (mp->peer_session_id);
  a.decap_mode = mp->decap_mode;
  a.raw_next_node_name = raw_name;
  a.raw_opaque = ntohl (mp->raw_opaque);
  a.decap_vrf_id = ntohl (mp->decap_vrf_id);
  a.encap_if_index = ntohl (mp->encap_if_index);

  rv = vnet_l2tpv2_add_del_session (&a, &sw_if_index);

out:
  REPLY_MACRO2 (VL_API_L2TPV2_ADD_DEL_SESSION_REPLY,
		({ rmp->sw_if_index = htonl (sw_if_index); }));
}

static void
send_l2tpv2_tunnel_details (l2tpv2_tunnel_t *t, u32 tunnel_index,
				   vl_api_registration_t *reg, u32 context)
{
  vl_api_l2tpv2_tunnel_details_t *rmp;
  l2tpv2_main_t *l2m = &l2tpv2_main;
  ip46_address_t local, peer;

  clib_memset (&local, 0, sizeof (local));
  clib_memset (&peer, 0, sizeof (peer));
  local.ip4.as_u32 = t->local_ip.as_u32;
  peer.ip4.as_u32 = t->peer_ip.as_u32;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_L2TPV2_TUNNEL_DETAILS + l2m->msg_id_base);
  rmp->context = context;
  rmp->tunnel_index = htonl (tunnel_index);
  ip_address_encode (&local, IP46_TYPE_IP4, &rmp->local_ip);
  ip_address_encode (&peer, IP46_TYPE_IP4, &rmp->peer_ip);
  rmp->local_tunnel_id = htons (t->local_tunnel_id);
  rmp->peer_tunnel_id = htons (t->peer_tunnel_id);
  rmp->local_udp_port = htons (t->local_udp_port);
  rmp->peer_udp_port = htons (t->peer_udp_port);
  rmp->df_bit = t->df_bit;
  rmp->ref_count = htonl (t->ref_count);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_l2tpv2_tunnel_dump_t_handler (
  vl_api_l2tpv2_tunnel_dump_t *mp)
{
  vl_api_registration_t *reg;
  l2tpv2_main_t *l2m = &l2tpv2_main;
  l2tpv2_tunnel_t *t;
  u32 want = ntohl (mp->tunnel_index);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (want == ~0)
    {
      pool_foreach (t, l2m->tunnels)
	{
	  send_l2tpv2_tunnel_details (t, t - l2m->tunnels, reg,
					     mp->context);
	}
    }
  else
    {
      if (pool_is_free_index (l2m->tunnels, want))
	return;
      t = pool_elt_at_index (l2m->tunnels, want);
      send_l2tpv2_tunnel_details (t, want, reg, mp->context);
    }
}

static void
send_l2tpv2_session_details (l2tpv2_session_t *s,
				    vl_api_registration_t *reg, u32 context)
{
  vl_api_l2tpv2_session_details_t *rmp;
  l2tpv2_main_t *l2m = &l2tpv2_main;
  l2tpv2_tunnel_t *t = pool_elt_at_index (l2m->tunnels, s->tunnel_index);
  ip46_address_t local, peer;

  clib_memset (&local, 0, sizeof (local));
  clib_memset (&peer, 0, sizeof (peer));
  local.ip4.as_u32 = t->local_ip.as_u32;
  peer.ip4.as_u32 = t->peer_ip.as_u32;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_L2TPV2_SESSION_DETAILS + l2m->msg_id_base);
  rmp->context = context;
  rmp->sw_if_index = htonl (s->sw_if_index);
  rmp->tunnel_index = htonl (s->tunnel_index);
  ip_address_encode (&local, IP46_TYPE_IP4, &rmp->local_ip);
  ip_address_encode (&peer, IP46_TYPE_IP4, &rmp->peer_ip);
  rmp->local_tunnel_id = htons (t->local_tunnel_id);
  rmp->local_session_id = htons (s->local_session_id);
  rmp->peer_session_id = htons (s->peer_session_id);
  rmp->decap_mode = s->decap_mode;
  rmp->raw_opaque = htonl (s->raw_opaque);
  rmp->decap_vrf_id = htonl (s->decap_fib_index);
  rmp->encap_if_index = htonl (s->encap_if_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_l2tpv2_session_dump_t_handler (
  vl_api_l2tpv2_session_dump_t *mp)
{
  vl_api_registration_t *reg;
  l2tpv2_main_t *l2m = &l2tpv2_main;
  l2tpv2_session_t *s;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (sw_if_index == ~0)
    {
      pool_foreach (s, l2m->sessions)
	{
	  send_l2tpv2_session_details (s, reg, mp->context);
	}
    }
  else
    {
      if (sw_if_index >= vec_len (l2m->session_index_by_sw_if_index)
	  || l2m->session_index_by_sw_if_index[sw_if_index] == ~0)
	return;
      s = pool_elt_at_index (l2m->sessions,
			     l2m->session_index_by_sw_if_index[sw_if_index]);
      send_l2tpv2_session_details (s, reg, mp->context);
    }
}

static void
vl_api_l2tpv2_set_session_ipv4_t_handler (
  vl_api_l2tpv2_set_session_ipv4_t *mp)
{
  vl_api_l2tpv2_set_session_ipv4_reply_t *rmp;
  l2tpv2_main_t *l2m = &l2tpv2_main;
  ip4_address_t addr;
  int rv;

  clib_memcpy (&addr, mp->client_ip, sizeof (addr));
  rv = vnet_l2tpv2_set_session_ipv4 (ntohl (mp->sw_if_index), &addr,
				     mp->is_add);

  REPLY_MACRO (VL_API_L2TPV2_SET_SESSION_IPV4_REPLY);
}

static void
vl_api_l2tpv2_set_session_ipv6_t_handler (
  vl_api_l2tpv2_set_session_ipv6_t *mp)
{
  vl_api_l2tpv2_set_session_ipv6_reply_t *rmp;
  l2tpv2_main_t *l2m = &l2tpv2_main;
  ip6_address_t addr;
  int rv;

  clib_memcpy (&addr, mp->client_ip, sizeof (addr));
  rv = vnet_l2tpv2_set_session_ipv6 (ntohl (mp->sw_if_index), &addr,
				     mp->is_add);

  REPLY_MACRO (VL_API_L2TPV2_SET_SESSION_IPV6_REPLY);
}

static void
vl_api_l2tpv2_set_delegated_prefix_t_handler (
  vl_api_l2tpv2_set_delegated_prefix_t *mp)
{
  vl_api_l2tpv2_set_delegated_prefix_reply_t *rmp;
  l2tpv2_main_t *l2m = &l2tpv2_main;
  ip6_address_t prefix, next_hop;
  int rv;

  clib_memcpy (&prefix, &mp->prefix.address.un.ip6, sizeof (prefix));
  clib_memcpy (&next_hop, mp->next_hop, sizeof (next_hop));
  rv = vnet_l2tpv2_set_delegated_prefix (ntohl (mp->sw_if_index), &prefix,
					 mp->prefix.len, &next_hop,
					 mp->is_add);

  REPLY_MACRO (VL_API_L2TPV2_SET_DELEGATED_PREFIX_REPLY);
}

#include <l2tpv2/l2tpv2.api.c>

static clib_error_t *
l2tpv2_api_hookup (vlib_main_t *vm)
{
  l2tpv2_main_t *l2m = &l2tpv2_main;
  l2m->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (l2tpv2_api_hookup);
