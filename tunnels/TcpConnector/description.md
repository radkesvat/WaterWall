
# TcpConnector Node

The `TcpConnector` node is responsible for establishing outgoing TCP connections to specified targets. Below is the JSON configuration structure for this node, along with detailed explanations of each field.

This node must be placed at the end of a chain

## Configuration Example

```json
{
    "name": "my connector",  
    "type": "TcpConnector",
    "settings": {
        "address": "httpforever.com", 
        "port": 80,
        "fwmark": 1,
        "nodelay": true,
        "fastopen": true,
        "reuseaddr": false,
        "domain-strategy": 0,
        "device": "device name"
    }
}
```

## Configuration Fields

### General Fields

- **`name`** *(string)*:  
  A user-defined name for the node. This is used for identification purposes.  
  - Example: `"my connector"`.

- **`type`** *(string)*:  
  The exact type name of the node. For this node, it must be `"TcpConnector"`.

---

### Settings (`settings`)

The `settings` object contains the configuration specific to the `TcpConnector` node.

#### Required Fields

- **`address`** *(string)*:  
  Specifies the target address to connect to. This can be an IPv4, IPv6, or domain name.  
  - Special values:
    - `"src_context->address"`: Uses the source address from the connection context.
    - `"dest_context->address"`: Uses the destination address from the connection context (typically filled by a protocol-aware node in the chain).  
  - Optional behavior: If the address ends with a CIDR range (e.g., `/32`), the node will intelligently select one IP from the range for each connection attempt. This behavior is referred to as `'freebind'`.  
  - Example: `"httpforever.com"`, `"192.168.1.1"`, `"2001:db8::1"`, `"src_context->address"`.

- **`port`** *(integer or string)*:  
  Specifies the target port to connect to.  
  - Special values:
    - `"src_context->port"`: Uses the source port from the connection context.
    - `"dest_context->port"`: Uses the destination port from the connection context.  

  - Example: `80`, `"src_context->port"`.

#### Optional Fields

- **`fwmark`** *(integer)*:  
  Sets the firewall mark (fwmark) on the socket for routing purposes.  
  - Default: Not set.  
  - Example: `1`.

- **`nodelay`** *(boolean)*:  
  Enables the TCP `NODELAY` option on the sockets, which disables Nagle's algorithm for reduced latency.  
  - Default: `true`.

- **`fastopen`** *(boolean)*:  
  Enables TCP Fast Open (TFO) for faster connection establishment.  
  - Default: `false`.

- **`reuseaddr`** *(boolean)*:  
  Enables the `SO_REUSEADDR` socket option, allowing the reuse of local addresses.  
  - Default: `false`.

- **`domain-strategy`** *(integer)*:  
  (Not yet implemented) Specifies the strategy for handling unresolved domain names, such as preferring IPv4 or IPv6.  
  - Default: `0`.

- **`device`** *(string)*:  
  Specifies the network device to use for the connection (e.g., a WireGuard device name).  
  - Default: Not set.  
  - Example: `"wg0"`.

---

### Behavior Notes

1. **Connection Context**:  
   - The `src_context` and `dest_context` fields allow dynamic resolution of addresses and ports based on the connection context. These are typically populated by protocol-aware nodes earlier in the chain.

2. **Freebind Behavior**:  
   - When the `address` field includes a CIDR range (e.g., `/32`), the node intelligently selects one IP from the range for each connection attempt. This is useful for load balancing or failover scenarios.

3. **Firewall Mark (`fwmark`)**:  
   - The `fwmark` option is particularly useful for advanced routing configurations, allowing traffic to be tagged and routed differently based on firewall rules.

4. **TCP Options**:  
   - The `nodelay`, `fastopen`, and `reuseaddr` options provide fine-grained control over socket behavior, optimizing performance and reliability based on your use case.

---

This documentation provides a comprehensive overview of the `TcpConnector` node and its configuration options. Use this as a reference when setting up your network chain.
```
