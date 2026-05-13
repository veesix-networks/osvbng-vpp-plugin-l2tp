# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# L2TPv2 Plugin (RFC 2661)
#
# Pure L2TPv2 dataplane: UDP/1701 demux (T-bit dispatched here by the punt
# plugin), per-session and per-tunnel bihash lookup tables, encap midchain,
# and configurable raw / IP decap modes. No PPPoE, AAA, or osvbng-specific
# bridging — this plugin is intended to be usable outside osvbng.

add_vpp_plugin(l2tpv2
  SOURCES
  l2tpv2.c
  l2tpv2_api.c
  l2tpv2_input.c
  l2tpv2_output.c
  l2tpv2_encap_raw.c
  l2tpv2_session.c

  API_FILES
  l2tpv2.api

  # Non-IP PPP frames decapsulated in DECAP_IP mode (LCP, CHAP, IPCP,
  # IPv6CP, etc.) are punted to userspace via the `osvbng-punt-shm-tx`
  # graph node, resolved by name at first frame. No symbol-level
  # dependency on osvbng_punt — plugins stay independently loadable.
)
