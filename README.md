# l2tpv2 — VPP L2TPv2 dataplane plugin

A VPP plugin that implements the L2TPv2 (RFC 2661) dataplane only. No
control channel, no PPP termination, no AAA. The plugin owns the
session table, the encap/decap, and the UDP/1701 handoff with a punt
plugin. Everything above that — control messages, FSMs, PPP — runs
in userspace and drives this plugin via binapi.

The plugin is deliberately transport-agnostic about what consumes the
decapsulated PPP frames, so it composes with multiple PPP terminators
and bridges (LAC modes, LNS modes, custom forwarding) without code
changes here.

## Scope

What the plugin does:

- Owns the per-tunnel and per-session lookup tables (bihash).
- Parses L2TPv2 data headers (variable header layout with L/S/O flags
  per RFC 2661 §3.1).
- Decapsulates inbound data packets and dispatches them, depending on
  the session's decap mode.
- Encapsulates outbound packets with IP + UDP + L2TPv2 framing.
- Resolves the egress next-hop through the FIB so peers reachable via
  any IP route (including loopback addresses) work without special
  configuration.

What the plugin does not do:

- Does not register UDP/1701 itself. A companion punt plugin owns the
  UDP port; this plugin receives `T=0` (data) frames via a graph arc
  and ignores `T=1` (control) frames at the dataplane layer.
- Does not parse AVPs, drive Ns/Nr, run Hello, build SCCRQ/ICRQ/ICCN,
  or any other control-plane work. A userspace process is responsible
  for that and programs sessions/tunnels through the binapi.
- Does not implement L2TPv3 (RFC 3931). The companion punt plugin can
  detect v3 and reject upstream.
- Does not encrypt or authenticate the L2TP payload. IPsec, if
  required, is layered underneath.

## Tunnel and session model

A **tunnel** is the addressing context for a peer pair: `(local_ip,
peer_ip, local_tunnel_id, peer_tunnel_id, local_udp_port,
peer_udp_port)`. One tunnel can carry many sessions. The plugin keeps
tunnel state in a bihash keyed by `(local_ip, peer_ip,
local_tunnel_id)` because that is what an inbound packet identifies it
with: per RFC 2661 §3.1 the tunnel ID the peer puts in packets to us
is the one we previously assigned and sent in our Assigned Tunnel ID
AVP.

A **session** is one PPP connection inside a tunnel. The session
bihash is keyed by `(local_ip, peer_ip, local_tunnel_id,
local_session_id)`.

Session IDs are unique within a tunnel; tunnel IDs are unique within a
`(local_ip, peer_ip)` pair. ID allocation is the responsibility of the
userspace control plane; the plugin only enforces uniqueness at
insert time.

## Decap modes

A session is created with one of two decap modes:

### `DECAP_IP`

For endpoints that terminate PPP locally. The session owns a
per-session vnet interface; FIB lookups for traffic destined to the
session land on that interface. On ingress, the input node strips
L2TP and the 2-byte PPP protocol field, sets `vnet_buffer(b)
->sw_if_index[VLIB_RX]` to the per-session interface, and dispatches
to `ip4-input` or `ip6-input` based on the PPP protocol field.

Egress uses a midchain adjacency on the per-session interface. The
rewrite carries IP + UDP + L2TPv2 (no L2 header) and stacks on the
FIB-resolved DPO for the peer IP. The FIB resolves ARP/glean for the
final L2 next-hop at packet time, so the peer can sit on any routed
address — including a loopback on the remote endpoint.

This is the mode an L2TPv2 endpoint that terminates PPP itself
(commonly called an LNS) uses.

### `DECAP_RAW`

For endpoints that bridge PPP frames to a different transport instead
of terminating them. There is no per-session vnet interface. On
ingress, the input node strips L2TP only (the PPP frame stays
intact), writes a caller-supplied `u32` opaque into
`vnet_buffer_l2tpv2_opaque(b)`, and forwards the buffer to a
caller-supplied graph next-node resolved by name at session-add time.

Egress uses a dedicated graph node, `l2tpv2-encap-raw`. The upstream
node (whatever produces PPP frames destined for an L2TPv2 session)
writes the session index into `vnet_buffer_l2tpv2_opaque(b)` and
enqueues to `l2tpv2-encap-raw`. The node prepends IP + UDP + L2TPv2
and forwards to `ip4-lookup`, so the FIB resolves the route to the
peer at packet time.

This is the mode an L2TPv2 endpoint that bridges PPP onto another
medium (commonly a LAC bridging PPPoE-on-ethernet to L2TP) uses.

## Composition with bridges

The plugin is intentionally unaware of what produces or consumes PPP
frames on the non-L2TP side. Composition with another VPP plugin
(PPPoE, ATM, raw socket, etc.) is via two contracts:

1. A graph next-node arc and a `u32` opaque, shared through
   `vnet_buffer_l2tpv2_opaque(b)` defined in `l2tpv2.h`.
2. The session's `raw_next_node_name` (set at session-add) resolves
   to a graph node by name. The consumer plugin registers its node;
   the L2TPv2 plugin does not care what the node does with the PPP
   frame.

A bridge consumer in another plugin must:

- Register a graph node that accepts buffers positioned at the PPP
  frame (starts with the 2-byte PPP protocol field).
- Read `vnet_buffer_l2tpv2_opaque(b)` to recover whatever session
  state was set at session-add (typically the partner session's index
  or sw_if_index in the consumer plugin's own pool).
- Produce frames in the opposite direction with the same opaque set
  and enqueue them to `l2tpv2-encap-raw`.

PPPoE LAC bridges, ATM PVC bridges, or any other PPP-bearing transport
follow this pattern. The reference PPPoE LAC bridge in osvbng's PPPoE
plugin is one consumer; nothing in this plugin assumes it is the only
one.

## Graph nodes

- `l2tpv2-input` — Receives `T=0` data frames from the punt plugin.
  Parses the L2TPv2 header (including optional Length, Sequence, and
  Offset fields), looks up the session, dispatches per decap mode.
- `l2tpv2-encap-raw` — Receives PPP frames from `DECAP_RAW`-mode
  bridges. Prepends IP + UDP + L2TPv2 and forwards to `ip4-lookup`.

The midchain encap used by `DECAP_IP` mode is not a registered graph
node; it is attached to each per-session vnet interface and entered
via the standard FIB → adjacency path.

## Punt-plugin contract

The plugin does not register UDP/1701 itself. A companion punt plugin
is expected to:

1. Register UDP/1701 globally via `udp_register_dst_port`.
2. Inspect the first byte's T-bit on each packet.
3. Forward `T=1` (control) packets to userspace (via shared memory,
   raw socket, or whatever the punt plugin chooses).
4. Forward `T=0` (data) packets to `l2tpv2-input` by name. The arc is
   resolved with `vlib_node_add_next` at first use.

The plugin will function on its own if the punt plugin is absent —
`l2tpv2-input` simply never receives packets — but the userspace
control plane has no path to send or receive L2TPv2 control
messages without a punt plugin.

The reference companion is osvbng-vpp-plugin-punt; any plugin that
satisfies the contract works.

## binapi

The plugin exposes:

```
osvbng_l2tpv2_add_del_tunnel  — add or remove a tunnel-level entry
osvbng_l2tpv2_add_del_session — add or remove a session, choosing
                                 decap mode and (for DECAP_RAW) the
                                 graph next-node to forward PPP
                                 frames to
osvbng_l2tpv2_tunnel_dump     — enumerate tunnels
osvbng_l2tpv2_session_dump    — enumerate sessions
```

See `l2tpv2.api` for the field definitions.

## CLI

For debugging and standalone use:

```
create l2tpv2 tunnel local-ip <ip> peer-ip <ip>
                    local-id <n> peer-id <n>
                    [local-port <n>] [peer-port <n>] [df] [del]

create l2tpv2 session local-ip <ip> peer-ip <ip>
                     local-tid <n> local-sid <n> peer-sid <n>
                     mode (ip|raw)
                     [decap-vrf-id <n>]
                     encap-if <intfc>
                     [raw-next-node <name>] [raw-opaque <hex>]
                     [del]

show l2tpv2 tunnel
show l2tpv2 session
```

The `encap-if` argument is currently required; setting it to a real
egress interface forces TX out that interface (mirrors the PPPoE
plugin's pattern, useful for point-to-point LAC↔LNS links). When
encap-if is not appropriate (peer reachable via loopback or any
routed path), supplying `~0` selects the FIB-resolved egress path.

## Multi-worker / RSS notes

The plugin is multi-worker safe by design. Reads from the bihash
tables are lock-free; writes use bucket-level locking. Pool elements
are cache-line aligned.

Within a single tunnel, all sessions share the same `(local_ip,
peer_ip, src_port, dst_port)` 5-tuple. Standard RSS will land every
packet of that tunnel on one worker. This is a property of
L2TPv2 over UDP, not a limitation of the plugin. Distributing
sessions across tunnels with distinct peer IPs lets RSS spread the
work.

## Known limitations

- The midchain installed for `DECAP_IP` sessions does not register a
  FIB-node back-walk. If the route to the peer changes after the
  session is up, the midchain continues to point at the original
  forwarding state. Sessions created after the route change pick up
  the new path; in-flight sessions need to be re-created (or
  `update_adj` re-triggered) to restack.
- L2TPv2 hidden AVPs (RFC 2661 §4.3) are control-plane scope and
  intentionally not addressed here.
- IPv6 transport for L2TPv2 is not yet implemented; only IPv4 outer.

## Files

| File | Purpose |
|---|---|
| `l2tpv2.h` | Plugin types, bihash key layouts, cross-plugin opaque macro. |
| `l2tpv2.c` | Plugin init, format helpers, CLI, hw class + midchain update. |
| `l2tpv2.api` | binapi message definitions. |
| `l2tpv2_api.c` | binapi handlers. |
| `l2tpv2_session.c` | Tunnel and session add/del. |
| `l2tpv2_input.c` | Ingress graph node. |
| `l2tpv2_output.c` | Midchain encap rewrite + per-packet fixup. |
| `l2tpv2_encap_raw.c` | DECAP_RAW-mode egress graph node. |
| `l2tpv2_error.def` | Error counter definitions. |
| `CMakeLists.txt` | Build glue. |
