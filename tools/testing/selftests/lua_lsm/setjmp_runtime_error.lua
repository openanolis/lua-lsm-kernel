-- SPDX-License-Identifier: GPL-2.0
-- Intentionally fails while the policy chunk is executed during registration.

local function fail_registration()
  error("intentional setjmp/longjmp recovery test")
end

fail_registration()

return {
  name = "setjmp_runtime_error",
}
