-- SPDX-License-Identifier: GPL-2.0
-- Private fixture for the concurrent unregister selftest.
local previous
local function valid(value)
  return value == nil or value == "a\0b" or value == "replacement"
      or value == 7 or value == true
end
return {
  name = "lifecycle",
  author = "OSPP",
  description = "Concurrent shared dictionary and module teardown test",
  license = "GPL-2.0",
  version = 1,

  file_open = function(file)
    local path = file:path()
    if path ~= "/tmp/lua-lsm-lifecycle-denied" then
      return true
    end
    -- The Lua copy from the previous open survives C-side overwrite/delete.
    if not valid(previous) then
      error("retained shared string changed")
    end
    previous = shared.runtime:get("churn")
    if not valid(previous) then
      error("invalid shared string during churn")
    end
    return path ~= shared.runtime:get("blocked_path")
  end,
}
