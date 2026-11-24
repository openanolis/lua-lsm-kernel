-- SPDX-License-Identifier: GPL-2.0
-- Always-allow policy used as the Lua-active baseline in CI matrices.
return {
	name = "allow-all",
	author = "Lua-LSM CI",
	description = "Allow every file_permission request",
	license = "GPL-2.0",
	version = 1,

	file_permission = function(file, mask)
		return true
	end,
}
