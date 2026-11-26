-- SPDX-License-Identifier: GPL-2.0
--
-- Minimal policy for the concurrent text-interface stress test.
-- The hook allows all access while exercising a second Lua call path.

return {
  name = "stress",
  author = "OSPP",
  description = "shdict concurrency stress policy",
  license = "GPL-2.0",
  version = 1,

  file_open = function(file)
    return true
  end,
}
