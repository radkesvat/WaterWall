# TcpListener Node

The `TcpListener` node is responsible for listening to incoming TCP connections. Below is the JSON configuration structure for this node, along with detailed explanations of each field.

## Configuration Example

```json
{
    "name": "my listener",  
    "type": "TcpListener",   
    "settings": {                   
        "address": "0.0.0.0", 
        "port": 8443,            
        "nodelay": true,         
        "balance-group": "balance group name", 
        "balance-interval": 100,
        "multiport-backend": "iptables",
        "whitelist": ["1.1.1.1/32", "2.2.2.2/32"],
        "blacklist": ["3.3.3.3/32", "4.4.4.4/32"]
    },
    "next": "any next node name"
}
```

## Configuration Fields

### General Fields

- **`name`** *(string)*:  
  A user-defined name for the node. This is used for identification purposes.

- **`type`** *(string)*:  
  The exact type name of the node. For this node, it must be `"TcpListener"`.

- **`next`** *(string)*:  
  Specifies the name of the next node in the chain that will handle the traffic after this node processes it.

---

### Settings (`settings`)

The `settings` object contains the configuration specific to the `TcpListener` node.

#### Required Fields

- **`address`** *(string)*:  
  The IP address on which the node will listen for incoming connections.  
  - Example: `"0.0.0.0"` (listens on all available interfaces).

- **`port`** *(integer or range)*:  
  The port number (or range of ports) on which the node will listen.  
  - Example: `8443` (single port) or `"8443-8450"` (port range).

#### Optional Fields

- **`nodelay`** *(boolean)*:  
  Enables the TCP `NODELAY` option on the sockets, which disables Nagle's algorithm for reduced latency.  
  - Default: `false`.

- **`balance-group`** *(string)*:  
  Defines a balance group name. When multiple sockets are part of the same balance group and listen on the same port, incoming clients are distributed (balanced) between them.  
  - Example: `"balance group name"`.

- **`balance-interval`** *(integer)*:  
  Specifies the interval (in milliseconds) after which the client IP is forgotten in the balance context. After this time, the next connection from the same client may be routed to a different socket in the balance group.  
  - Default: Not set (only relevant when `balance-group` is defined).  
  - Example: `100`.

- **`multiport-backend`** *(string)*:  
  Specifies the backend method used to implement multiport support when a port range is provided.  
  - Possible values: `"iptables"` (default), `"socket"`.  
  - Example: `"iptables"`.

- **`whitelist`** *(array of strings)*:  
  A list of IP addresses or CIDR ranges that are allowed to connect to this node. If a client's IP is not in this list, the connection will be rejected.  
  - Supports both IPv4 and IPv6.  
  - Example: `["1.1.1.1/32", "2.2.2.2/32"]`.

- **`blacklist`** *(array of strings)*:  
  A list of IP addresses or CIDR ranges that are explicitly denied from connecting to this node.  
  - Supports both IPv4 and IPv6.  
  - Example: `["3.3.3.3/32", "4.4.4.4/32"]`.

---

### Behavior Notes

1. **Whitelist and Blacklist**:  
   - If both `whitelist` and `blacklist` are defined, the `whitelist` takes precedence.  
   - If a client is rejected due to these rules, another socket listening on the same port (even outside the balance group) can take ownership of the connection if it does not have conflicting rules.

2. **Balance Group**:  
   - The `balance-group` feature allows multiple sockets to share the load of incoming connections on the same port.  
   - The `balance-interval` ensures that clients are periodically redistributed across sockets in the group.

3. **Multiport Backend**:  
   - The `multiport-backend` determines how port ranges are handled.  
   - `"iptables"` uses system-level firewall rules, while `"socket"` handles it directly within the application.

---

This documentation provides a comprehensive overview of the `TcpListener` node and its configuration options. Use this as a reference when setting up your network chain.
```