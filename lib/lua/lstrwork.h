/* SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause */
#ifndef lstrwork_h
#define lstrwork_h

#include <linux/types.h>

#define LUA_STRING_WORK_LIMIT 65536ULL

typedef struct StrWorkBudget {
  u64 remaining;
} StrWorkBudget;

static inline bool strwork_debit (StrWorkBudget *b, u64 cost) {
  if (cost > b->remaining) {
    b->remaining = 0;
    return false;
  }
  b->remaining -= cost;
  return true;
}

#endif
