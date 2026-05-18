# Disturber Node

`Disturber` is a test tunnel used to simulate unreliable network behavior inside a WaterWall chain. It is designed to help validate other tunnels by injecting drops, corruption, duplication, reordering, delays, hangs, and abrupt closes.

In practice, this tunnel is inserted into a test chain around the tunnel or transport behavior you want to stress.

## What It Does

- Forwards normal line events and payload through the chain.
- Randomly closes connections at startup or mid-stream.
- Randomly drops payload.
- Randomly duplicates payload.
- Randomly corrupts payload bytes.
- Randomly reorders payload by holding one payload and releasing it later.
- Randomly delays payload within a configurable delay range.
- Can place a connection into a dead-hang state where payload stops flowing.

This makes `Disturber` useful for resilience testing, crash detection, reconnection testing, and edge-case validation of higher-level tunnels.

## Typical Placement

A common layout is:

- some tunnel or transport under test
- `Disturber`
- the next part of the test path

or:

- test client side
- `Disturber`
- tunnel under test
- another `Disturber`
- test server side

It can be placed almost anywhere in a chain where you want to simulate hostile or unstable network conditions.

## Configuration Example

```json
{
  "name": "disturber",
  "type": "Disturber",
  "settings": {
    "disturb-upstream": true,
    "disturb-downstream": false,
    "chance_instant_close": 5,
    "chance_middle_close": 2,
    "chance_payload_corruption": 3,
    "chance_payload_loss": 10,
    "chance_payload_duplication": 2,
    "chance_payload_out_of_order": 4,
    "chance_payload_delay": 15,
    "chance_connection_deadhang": 1,
    "delay_min_ms": 50,
    "delay_max_ms": 300
  },
  "next": "next-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"Disturber"`.

### `settings`

All disturbance controls are optional. If omitted, they default to `0` and the tunnel behaves like a pass-through node.

## Optional `settings` Fields

All chance fields are integer percentages interpreted as a probability for that event when the relevant callback runs.

- `disturb-upstream` `(boolean)`
  Enables disturbance injection on upstream payload and upstream-init close handling.
  Default: `true`

- `disturb-downstream` `(boolean)`
  Enables disturbance injection on downstream payload and downstream-init close handling.
  Default: `false`

- `chance_instant_close` `(integer)`
  Chance that a direction is closed immediately when init arrives for an enabled direction.

- `chance_middle_close` `(integer)`
  Chance that a connection is closed while payload is being forwarded.

- `chance_payload_corruption` `(integer)`
  Chance that payload bytes are modified before forwarding.

- `chance_payload_loss` `(integer)`
  Chance that a payload is dropped entirely.

- `chance_payload_duplication` `(integer)`
  Chance that a copy of the payload is sent an extra time.

- `chance_payload_out_of_order` `(integer)`
  Chance that one payload is held so it can be released out of order relative to later payload.

- `chance_payload_delay` `(integer)`
  Chance that payload is delayed before being forwarded.

- `chance_connection_deadhang` `(integer)`
  Chance that a connection enters a dead-hang state where further payload stops flowing.

- `delay_min_ms` `(integer)`
  Minimum delay used when payload delay is triggered.

  Negative values are clamped to `0`.

- `delay_max_ms` `(integer)`
  Maximum delay used when payload delay is triggered.

  If it is lower than `delay_min_ms`, it is clamped up to `delay_min_ms`.

## Detailed Behavior

### Connection lifecycle simulation

When a new upstream connection is initialized:

- `Disturber` initializes its per-line state
- optionally closes the connection immediately based on `chance_instant_close`
- otherwise forwards init to the next node

During normal payload forwarding, it may also close the connection mid-stream based on `chance_middle_close`.

This lets you test both startup failure handling and unexpected disconnect handling.

### Payload mutation behavior

For each enabled-direction payload, `Disturber` evaluates a sequence of possible disturbances.

The available behaviors are:

- drop the payload completely
- duplicate the payload by sending an extra copy
- corrupt part of the payload
- hold a payload for later to create out-of-order delivery
- delay the payload by a random amount
- mark the connection as dead-hung so future payload is silently discarded

Corruption is applied by modifying random payload bytes. The current implementation corrupts up to roughly 10% of the payload, with at least one byte changed when payload is non-empty.

### Reordering model

`Disturber` keeps at most one held payload per line per enabled direction for out-of-order delivery.

When out-of-order mode triggers:

- the current payload is stored
- the next payload that arrives can cause the held payload to be sent first
- then the current payload is forwarded after it

This creates a simple but effective packet reordering effect.

### Delay model

When delayed delivery triggers:

- a random delay between `delay_min_ms` and `delay_max_ms` is chosen
- the payload is scheduled for later forwarding on the line

This is useful for testing timeout behavior, jitter tolerance, retransmission logic, and buffering correctness.

### Dead-hang model

If dead-hang triggers on a line:

- the line remains present
- payload stops being forwarded
- later payload is discarded

This simulates a connection that appears alive at the structural level but stops making forward progress.

### Directional behavior

By default, `Disturber` preserves its original behavior and injects disturbances only on the upstream data path.
Set `disturb-downstream=true` to apply the same payload disturbance model to downstream payloads. Set
`disturb-upstream=false` when only the downstream direction should be disturbed.

## Notes And Caveats

- All disturbance settings default to `0`, so the tunnel can be enabled gradually.
- This node is intended for testing and validation, not for production traffic.
- Combining multiple high probability values can create very chaotic behavior quickly.
- If you enable payload delay, configure a meaningful `delay_min_ms` and `delay_max_ms` range so the simulated network behavior matches the scenario you want to test.
