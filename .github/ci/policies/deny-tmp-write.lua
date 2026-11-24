-- SPDX-License-Identifier: GPL-2.0
-- Deny writes to /tmp/lua-lsm-denied* while allowing everything else.
local errno = require("errno")

return {
	name = "deny-tmp-write",
	author = "Lua-LSM CI",
	description = "Deny writes to /tmp/lua-lsm-denied*",
	license = "GPL-2.0",
	version = 1,

	file_permission = function(file, mask)
		-- In-kernel Lua 5.1 has no bitwise operators: MAY_WRITE (2) is
		-- set when mask % 4 >= 2.
		if mask % 4 < 2 then
			return true
		end
		local path = file:path()
		if path and path:match("^/tmp/lua%-lsm%-denied") then
			return false, errno.EACCES
		end
		return true
	end,
}
