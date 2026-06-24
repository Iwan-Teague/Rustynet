# Rustynet Node Map — data contract

The visualisation is deliberately decoupled from any data source. It consumes a
single plain-JSON graph and exposes a tiny imperative API. Wire this to the
real Rustynet daemon later (e.g. a WebSocket / SSE feed, or a Tauri command that
serializes the membership + dataplane view).

## Graph shape

```jsonc
{
  "nodes": [
    {
      "id": "anchor-eu",          // required, stable unique key
      "label": "anchor-eu",       // optional display name (defaults to id)
      "role": "anchor",           // see Roles below; unknown -> grey "Unknown"
      "status": "online",         // see Statuses below; unknown -> "offline"
      "position": { "x": 0, "y": 0, "z": 0 }, // OPTIONAL: pin the node here.
                                              // Omit to let the force layout place it.
      "meta": {                   // OPTIONAL free-form, shown in the inspector
        "address": "100.64.0.10",
        "os": "linux",            // linux | macos | windows | ios | android | ...
        "lastSeen": "2026-06-21T09:00:00Z"
      }
    }
  ],
  "edges": [
    {
      "from": "laptop-mac",       // node id
      "to": "anchor-eu",          // node id
      "kind": "data_path",        // see Edge kinds below (default: data_path)
      "active": true              // OPTIONAL (default true); false dims the link
    }
  ]
}
```

A node going **offline / powered off** is just a `status` change — keep the node
in the graph so it stays visible (dimmed). Remove it from `nodes` only when it
has truly left the network.

## Roles

Defined in the `ROLES` config in `index.html`. Each role has a colour, label,
description, and relative size. Current set (mirrors the Rustynet role +
capability model):

| role | meaning |
|------|---------|
| `client` | endpoint device |
| `admin` | control / operator node |
| `anchor` | coordination anchor |
| `relay` | zero-ingress relay |
| `exit` | internet egress |
| `blind_exit` | egress with no plaintext visibility |
| `nas` | storage service |
| `llm` | inference service |

Colours are placeholders — change them in one place (`ROLES`). Add a new role by
adding one entry; the legend updates automatically from whatever roles are
present in the data.

## Statuses

Defined in the `STATUS` config. Each status controls brightness, glow, pulse,
desaturation, and flicker of the node's "ball of light":

| status | reads as |
|--------|----------|
| `online` | bright, gently pulsing, full colour |
| `connecting` | flickering, slightly desaturated |
| `offline` | dim, mostly grey (known but unreachable) |
| `powered_off` | very faint (known but off) |

## Edge kinds

Defined in `EDGE_KINDS`:

| kind | meaning | rendering |
|------|---------|-----------|
| `data_path` | active traffic path | bright line + travelling flow particles |
| `control` | signalling / control link | thin steady line |
| `potential` | known but idle link | very faint line |

Flow particles only travel when both endpoints are `online` and the edge is
`active`, so the animation always reflects real reachability.

## How the native tool consumes this

The native app (`src/main.rs`) reads this JSON either from a file argument
(`cargo run -- topology.json`) or falls back to built-in demo data:

```rust
// load_graph() reads the JSON into the input DTOs (GraphDto/NodeDto/EdgeDto),
// then Graph::from_dto(..) builds the live model.
let graph = load_graph();
```

### Suggested wiring (later)

To make it live, have `rustynetd` emit this JSON and feed it in continuously.
Two simple options:

- **Poll a file / endpoint:** re-read the JSON on an interval and call
  `Graph::from_dto(..)` to rebuild, or diff against the current model.
- **Stream deltas over a local socket:** the daemon emits a full `snapshot`
  on connect, then incremental `node_update` messages; apply each patch to the
  matching `Node` in place (status/role changes are cheap; a role change just
  re-reads `role_style`).

Replace `load_graph()` / the `simulate()` demo loop in `src/main.rs` with the
real feed. Keep the JSON contract above stable so the view and the backend can
evolve independently.
