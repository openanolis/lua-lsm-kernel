# API

## Module format

A module is a Lua chunk that returns a table with metadata and hook functions.

Required fields:
- `name` (string)
- `author` (string)
- `description` (string)
- `license` (string)
- `version` (number)

Hook functions are keyed by the supported LSM hook name (e.g. `file_open`).
Use `kernel.lsm_funcs()` to enumerate the supported set. Lua-LSM does not
expose unsupported hooks through its module APIs or observability output;
the current unsupported set includes `getprocattr`, `setprocattr`, and
`lsmprop_to_secctx`.

Example:

```lua
local errno = require("errno")

return {
  name = "demo",
  author = "example",
  description = "Example module",
  license = "GPL-2.0",
  version = 1,

  file_open = function(file, cred)
    local path = file:path()
    if path and path:match("^/etc/shadow$") then
      return false, errno.EPERM
    end
    return true
  end,
}
```

## Hook return values (int-return hooks)

- `nil` or no return: default value
- `true`: allow (0)
- `false`: deny (-EPERM)
- `false, errno`: deny (-errno)
- `nil, errno`: deny (-errno)

Use `require("errno")` to access errno constants.

## Listing hook names

From Lua:

```lua
local kernel = require("kernel")
local hooks = kernel.lsm_funcs()
```

From userspace (if stats enabled):

```
cat /sys/kernel/security/lua/lsm_funcs
```

Both interfaces list only hooks that Lua-LSM actually supports and registers.

## Built-in libraries

Lua-LSM preloads these libraries (use `require()`):

- `kernel`: task, cred, printk, time, and helper utilities
- `fs`: file/dentry/inode/path helpers
- `net`: socket and address helpers
- `errno`: errno constants + `errname()`
- `capability`: kernel capability helpers
- `signal`: signal helpers

## Common object methods (examples)

Task (`task`):
- `task:pids()` -> pid, tgid
- `task:comm()` -> comm string
- `task:cred()` -> cred object

File (`file`):
- `file:path()` -> path string or nil, err
- `file:inode()` -> inode object

Inode (`inode`):
- `inode:ino()` -> inode number
- `inode:mode()` -> table or boolean checks
- `inode:ids()` -> uid, gid

Dentry (`dentry`):
- `dentry:path()` -> path string

Sock (`sock`):
- `sock:suites()` -> family, type, protocol strings
- `sock:proto()` -> raw `sk_protocol` number, needed for non-IP protocol
  namespaces such as netlink's `NETLINK_GENERIC`

Skb (`skb`):
- `skb:sock()` -> owning sock, or `nil`. Always a full sock: a half-open
  (`SYN_RECV`) connection resolves to its listening sock and a time-wait sock
  yields `nil`, because those mini-sock forms lack the fields the `sock`
  accessors read
- `skb:len()` -> length in bytes of the skb's data window
- `skb:read(off, len)` -> `len` bytes of the data window as a string
  (`len` <= 256), or `nil` when `off` or `off + len` falls outside it

`skb:read()` returns raw bytes; decode multi-byte fields in Lua (e.g. with
`string.byte`), since the in-kernel Lua has no bit library. Reads are
bounds-checked and return `nil` instead of raising, so the policy decides the
verdict. Note that a Lua error inside a hook falls back to that hook's default
return value, which is "allow" for most hooks; wrap parsing in `pcall()` when
the policy must fail closed.

## The skb data window

`skb:len()` and `skb:read()` share one base, the skb's data window: the
`skb->len` bytes starting at `skb->data`. Offset 0 of `skb:read()` is the first
byte of that window, and a read reaching into the skb's paged fragments is
stitched together transparently.

That first byte is not the start of the packet. Each protocol layer consumes its
header by advancing `skb->data` past it, so where the window begins is a
property of the hook rather than of the packet: by the time any socket-level
hook runs on the IPv4 receive path the network header is already consumed, and
SCTP has consumed both its chunk header and the INIT header. An offset is
therefore only meaningful for the one hook it was computed for, and getting it
wrong is quiet: an out-of-range read yields `nil`, an in-range one yields
whatever field actually sits there, so a policy built on the wrong base can look
like it works.

Bases verified against this tree:

| hook | first byte of the window | hook called from |
| --- | --- | --- |
| `netlink_send` | the netlink message header (`struct nlmsghdr`) | `netlink_sendmsg()` |
| `socket_sock_rcv_skb` | the TCP or UDP header | `tcp_filter()`, `udp_queue_rcv_one_skb()` |
| `inet_conn_request` | the TCP header of the SYN | `tcp_v4_route_req()`, `cookie_v4_check()` |
| `inet_conn_established` | the TCP header of the SYN-ACK | `tcp_finish_connect()` |
| `socket_getpeersec_dgram` | the UDP header | `ip_cmsg_recv_security()` |
| `sctp_assoc_request` | the INIT chunk's parameters, for the INIT state | `sctp_sf_do_5_1B_init()` |
| `xfrm_decode_session` | not established; verify before relying on it | `__xfrm_decode_session()` |

Two further details about the hooks above:
- Under `netlink_send` the window spans everything one `sendmsg()` wrote, so a
  batch arrives as consecutive length-delimited messages, not one message.
- `socket_sock_rcv_skb` runs before the socket filter can trim the skb, so the
  window is the untrimmed length.

For a full list, see the method tables in `lua_kernel.c`, `lua_fs.c`, and
`lua_net.c`.
