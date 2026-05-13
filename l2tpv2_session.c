/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * L2TPv2 tunnel and session add/del helpers.
 */

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/fib/fib_table.h>
#include <vnet/interface.h>
#include <l2tpv2/l2tpv2.h>

extern u8 *l2tpv2_build_rewrite (vnet_main_t *vnm, u32 sw_if_index,
					vnet_link_t link_type,
					const void *dst_address);

extern vnet_device_class_t l2tpv2_device_class;
extern vnet_hw_interface_class_t l2tpv2_hw_class;

int
vnet_l2tpv2_add_del_tunnel (vnet_l2tpv2_add_del_tunnel_args_t *a,
				   u32 *tunnel_indexp)
{
  l2tpv2_main_t *l2m = &l2tpv2_main;
  l2tpv2_tunnel_t *t = 0;
  clib_bihash_kv_16_8_t kv;
  l2tpv2_tunnel_key_t key;

  l2tpv2_tunnel_key_set (&key, &a->local_ip, &a->peer_ip,
				a->local_tunnel_id);
  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];

  if (a->is_add)
    {
      kv.value = ~0ULL;
      if (clib_bihash_search_inline_16_8 (&l2m->tunnel_table, &kv) == 0)
	return VNET_API_ERROR_TUNNEL_EXIST;

      pool_get_aligned (l2m->tunnels, t, CLIB_CACHE_LINE_BYTES);
      clib_memset (t, 0, sizeof (*t));

      t->local_ip.as_u32 = a->local_ip.as_u32;
      t->peer_ip.as_u32 = a->peer_ip.as_u32;
      t->local_tunnel_id = a->local_tunnel_id;
      t->peer_tunnel_id = a->peer_tunnel_id;
      t->local_udp_port = a->local_udp_port ? a->local_udp_port : L2TPV2_UDP_PORT;
      t->peer_udp_port = a->peer_udp_port ? a->peer_udp_port : L2TPV2_UDP_PORT;
      t->df_bit = a->df_bit;
      t->ref_count = 0;
      t->encap_fib_index = 0; /* default FIB (global table 0) */
      t->fib_entry_index = FIB_NODE_INDEX_INVALID;

      kv.value = t - l2m->tunnels;
      clib_bihash_add_del_16_8 (&l2m->tunnel_table, &kv, 1 /* is_add */);

      if (tunnel_indexp)
	*tunnel_indexp = t - l2m->tunnels;
      return 0;
    }

  /* delete */
  kv.value = ~0ULL;
  if (clib_bihash_search_inline_16_8 (&l2m->tunnel_table, &kv) != 0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  t = pool_elt_at_index (l2m->tunnels, (u32) kv.value);
  if (t->ref_count != 0)
    return VNET_API_ERROR_INSTANCE_IN_USE;

  clib_bihash_add_del_16_8 (&l2m->tunnel_table, &kv, 0 /* is_del */);
  pool_put (l2m->tunnels, t);

  if (tunnel_indexp)
    *tunnel_indexp = ~0;
  return 0;
}

static int
l2tpv2_resolve_decap_fib (u32 decap_vrf_id, u32 *fib_index_out)
{
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP4, decap_vrf_id);
  if (fib_index == ~0)
    return VNET_API_ERROR_NO_SUCH_FIB;
  *fib_index_out = fib_index;
  return 0;
}

int
vnet_l2tpv2_add_del_session (
  vnet_l2tpv2_add_del_session_args_t *a, u32 *sw_if_indexp)
{
  l2tpv2_main_t *l2m = &l2tpv2_main;
  l2tpv2_session_t *s = 0;
  l2tpv2_tunnel_t *t = 0;
  vnet_main_t *vnm = l2m->vnet_main;
  clib_bihash_kv_16_8_t skv;
  clib_bihash_kv_16_8_t tkv;
  l2tpv2_session_key_t skey;
  l2tpv2_tunnel_key_t tkey;
  u32 sw_if_index = ~0;
  u32 hw_if_index = ~0;
  u32 tunnel_index;
  int rv;

  /* Locate the owning tunnel. */
  l2tpv2_tunnel_key_set (&tkey, &a->local_ip, &a->peer_ip,
				a->local_tunnel_id);
  tkv.key[0] = tkey.as_u64[0];
  tkv.key[1] = tkey.as_u64[1];
  tkv.value = ~0ULL;

  if (clib_bihash_search_inline_16_8 (&l2m->tunnel_table, &tkv) != 0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  tunnel_index = (u32) tkv.value;
  t = pool_elt_at_index (l2m->tunnels, tunnel_index);

  l2tpv2_session_key_set (&skey, &a->local_ip, &a->peer_ip,
				 a->local_tunnel_id, a->local_session_id);
  skv.key[0] = skey.as_u64[0];
  skv.key[1] = skey.as_u64[1];

  if (a->is_add)
    {
      skv.value = ~0ULL;
      if (clib_bihash_search_inline_16_8 (&l2m->session_table, &skv) == 0)
	return VNET_API_ERROR_TUNNEL_EXIST;

      pool_get_aligned (l2m->sessions, s, CLIB_CACHE_LINE_BYTES);
      clib_memset (s, 0, sizeof (*s));

      s->tunnel_index = tunnel_index;
      s->local_session_id = a->local_session_id;
      s->peer_session_id = a->peer_session_id;
      s->decap_mode = a->decap_mode;
      s->encap_if_index = a->encap_if_index;
      s->raw_next_node_index = ~0;
      s->raw_opaque = 0;
      s->sw_if_index = ~0;
      s->hw_if_index = ~0;
      s->decap_fib_index = 0;

      if (a->decap_mode == L2TPV2_DECAP_RAW)
	{
	  vlib_node_t *next_node = 0;
	  if (a->raw_next_node_name == 0 || a->raw_next_node_name[0] == 0)
	    {
	      pool_put (l2m->sessions, s);
	      return VNET_API_ERROR_INVALID_VALUE;
	    }
	  next_node =
	    vlib_get_node_by_name (l2m->vlib_main, (u8 *) a->raw_next_node_name);
	  if (next_node == 0)
	    {
	      pool_put (l2m->sessions, s);
	      return VNET_API_ERROR_NO_SUCH_NODE;
	    }
	  s->raw_next_node_index = next_node->index;
	  s->raw_opaque = a->raw_opaque;
	}
      else if (a->decap_mode == L2TPV2_DECAP_IP)
	{
	  rv = l2tpv2_resolve_decap_fib (a->decap_vrf_id,
						&s->decap_fib_index);
	  if (rv != 0)
	    {
	      pool_put (l2m->sessions, s);
	      return rv;
	    }

	  /* Register a per-session vnet interface so FIB / counters work. */
	  if (vec_len (l2m->free_session_hw_if_indices) > 0)
	    {
	      vnet_hw_interface_t *hi;
	      hw_if_index = l2m->free_session_hw_if_indices
		[vec_len (l2m->free_session_hw_if_indices) - 1];
	      vec_dec_len (l2m->free_session_hw_if_indices, 1);

	      hi = vnet_get_hw_interface (vnm, hw_if_index);
	      hi->dev_instance = s - l2m->sessions;
	      hi->hw_instance = hi->dev_instance;
	    }
	  else
	    {
	      hw_if_index = vnet_register_interface (
		vnm, l2tpv2_device_class.index, s - l2m->sessions,
		l2tpv2_hw_class.index, s - l2m->sessions);
	    }

	  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
	  s->hw_if_index = hw_if_index;
	  s->sw_if_index = sw_if_index = hi->sw_if_index;

	  vec_validate_init_empty (l2m->session_index_by_sw_if_index,
				   sw_if_index, ~0);
	  l2m->session_index_by_sw_if_index[sw_if_index] = s - l2m->sessions;

	  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
	  si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
	  vnet_sw_interface_set_flags (vnm, sw_if_index,
				       VNET_SW_INTERFACE_FLAG_ADMIN_UP);
	}
      else
	{
	  pool_put (l2m->sessions, s);
	  return VNET_API_ERROR_INVALID_VALUE;
	}

      skv.value = s - l2m->sessions;
      clib_bihash_add_del_16_8 (&l2m->session_table, &skv, 1 /* is_add */);

      t->ref_count++;

      /* For DECAP_IP the reply carries the per-session vnet sw_if_index
       * (consumers bind it for FIB / counters). For DECAP_RAW there is
       * no vnet interface, but the consumer (osvbng PPPoE LAC bridge)
       * needs the L2TPv2 session pool index to stash as the buffer
       * opaque on the subscriber→LNS path — l2tpv2-encap-raw reads it
       * back as `session_index`. Overload the reply field with that
       * pool index in RAW mode. */
      if (sw_if_indexp)
	*sw_if_indexp = (a->decap_mode == L2TPV2_DECAP_RAW)
			  ? (u32) (s - l2m->sessions)
			  : sw_if_index;
      return 0;
    }

  /* delete */
  skv.value = ~0ULL;
  if (clib_bihash_search_inline_16_8 (&l2m->session_table, &skv) != 0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  s = pool_elt_at_index (l2m->sessions, (u32) skv.value);

  if (s->decap_mode == L2TPV2_DECAP_IP && s->sw_if_index != ~0)
    {
      vnet_sw_interface_set_flags (vnm, s->sw_if_index, 0 /* down */);
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, s->sw_if_index);
      si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;
      vec_add1 (l2m->free_session_hw_if_indices, s->hw_if_index);
      l2m->session_index_by_sw_if_index[s->sw_if_index] = ~0;
      sw_if_index = s->sw_if_index;
    }

  clib_bihash_add_del_16_8 (&l2m->session_table, &skv, 0 /* is_del */);

  if (t->ref_count > 0)
    t->ref_count--;

  pool_put (l2m->sessions, s);

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;
  return 0;
}
