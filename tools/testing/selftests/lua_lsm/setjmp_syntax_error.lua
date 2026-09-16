-- SPDX-License-Identifier: GPL-2.0
-- Intentionally invalid: verifies protected recovery from a parser error.

return {
  name = "setjmp_syntax_error",
  file_open = function(file)
    return true
  -- Deliberately omit the closing "end" and table brace.
