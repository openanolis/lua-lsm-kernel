-- SPDX-License-Identifier: GPL-2.0
-- Valid policy loaded after intentional Lua errors.

return {
  name = "setjmp_recovery",
  author = "OSPP",
  description = "Lua error recovery validation policy",
  license = "GPL-2.0",
  version = 1,

  file_open = function(file)
    local path = file:path()

    if path == "/tmp/setjmp-hook-error" then
      error("intentional file_open runtime error")
    end

    return path ~= "/tmp/setjmp-denied"
  end,
}
