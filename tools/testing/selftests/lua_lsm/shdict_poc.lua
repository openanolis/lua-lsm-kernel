-- SPDX-License-Identifier: GPL-2.0
--
-- securityfs shared-dictionary text-interface PoC policy.
--
-- The file_open hook reads shared.runtime.blocked_path on every open and
-- denies access when the opened path equals the configured string. The
-- /sys/kernel/security/lua/shdict parses a compact userspace command and
-- invokes the existing shared.runtime Lua API through an internal bridge.
--
-- The hook additionally:
--   * stores a real kernel lightuserdata under "ptr", so the securityfs
--     result path must refuse to export it (-EOPNOTSUPP) instead of leaking
--     the kernel address.  The module environment is keyed by a raw
--     lightuserdata (the same &_module_sentinel used as MODULE_KEY), so
--     the policy harvests it with getfenv(1) + pairs();
--   * verifies that a string value written from securityfs keeps its
--     embedded NULs when read from Lua ("probe_expected" is compared
--     against the literal "a\0b" and the result is published back under
--     "probe_mismatch");
--   * one-shot probes for delete (probe_del_requested -> probe_del = nil)
--     and for an overlong result (probe_long_requested -> probe_long).
--
-- Diagnostic keys written on every dispatch (readable via shdict):
--   probe_env_n       number of raw keys in the hook environment
--   probe_ptr_found   bool: was a lightuserdata key found?
--   probe_ptr_type    string: type() of the harvested marker, if any

return {
  name = "demo",
  author = "OSPP",
  description = "securityfs shared dict Lua execution PoC",
  license = "GPL-2.0",
  version = 3,

  file_open = function(file)
    local runtime = shared.runtime          -- creates the shared dict

    local marker
    local nenv = 0
    -- getfenv(1): the base library here is 5.2-style, so level 0 is the
    -- C getfenv itself (returns _G) and level 1 is this hook function.
    local menv = getfenv(1)
    for k in pairs(menv) do
      nenv = nenv + 1
      if type(k) == "userdata" then         -- raw kernel lightuserdata key
        marker = k
      end
    end
    runtime.probe_env_n = nenv
    runtime.probe_ptr_found = (marker ~= nil)
    if marker then
      runtime.ptr = marker                  -- lightuserdata value
      runtime.probe_ptr_type = type(marker)
    end

    if runtime.probe_expected then
      runtime.probe_mismatch = (runtime.probe_expected ~= "a\0b")
    end

    -- one-shot probe: store a Lua-side string longer than the securityfs
    -- response buffer; returning it must fail with -E2BIG
    if runtime.probe_long_requested then
      local long = ""
      for i = 1, 4097 do
        long = long .. "z"
      end
      runtime.probe_long = long
      runtime.probe_long_requested = nil
    end

    -- one-shot probe: delete a key from Lua so the node/string recycle
    -- path (shared.runtime.key = nil) is exercised and leak-checked
    if runtime.probe_del_requested then
      runtime.probe_del = nil
      runtime.probe_del_requested = nil
    end

    local blocked = runtime.blocked_path    -- string or nil
    local path = file:path()
    if path and blocked and path == blocked then
      return false                          -- deny
    end
    return true
  end,
}
