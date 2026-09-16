// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for the RISC-V setjmp()/longjmp() implementation.
 */

#include <kunit/test.h>
#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/setjmp.h>

struct setjmp_test_state {
	struct label_t label;
	int jumped;
	int ret;
};

static noinline void jump_to_label(struct kunit *test,
				   struct label_t *label, int value)
{
	longjmp(label, value);
	KUNIT_FAIL(test, "longjmp() unexpectedly returned");
}

static noinline void jump_level_three(struct kunit *test,
				      struct label_t *label)
{
	jump_to_label(test, label, 73);
	KUNIT_FAIL(test, "third jump level unexpectedly returned");
}

static noinline void jump_level_two(struct kunit *test,
				    struct label_t *label)
{
	jump_level_three(test, label);
	KUNIT_FAIL(test, "second jump level unexpectedly returned");
}

static noinline void jump_level_one(struct kunit *test,
				    struct label_t *label)
{
	jump_level_two(test, label);
	KUNIT_FAIL(test, "first jump level unexpectedly returned");
}

static void riscv_setjmp_zero_value_test(struct kunit *test)
{
	struct setjmp_test_state *state;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);
	WRITE_ONCE(state->ret, setjmp(&state->label));
	if (!READ_ONCE(state->jumped)) {
		KUNIT_EXPECT_EQ(test, READ_ONCE(state->ret), 0);
		WRITE_ONCE(state->jumped, 1);
		jump_to_label(test, &state->label, 0);
	}

	KUNIT_EXPECT_EQ(test, READ_ONCE(state->jumped), 1);
	KUNIT_EXPECT_EQ(test, READ_ONCE(state->ret), 1);
}

static void riscv_setjmp_nonzero_value_test(struct kunit *test)
{
	struct setjmp_test_state *state;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);
	WRITE_ONCE(state->ret, setjmp(&state->label));
	if (!READ_ONCE(state->jumped)) {
		KUNIT_EXPECT_EQ(test, READ_ONCE(state->ret), 0);
		WRITE_ONCE(state->jumped, 1);
		jump_to_label(test, &state->label, 37);
	}

	KUNIT_EXPECT_EQ(test, READ_ONCE(state->jumped), 1);
	KUNIT_EXPECT_EQ(test, READ_ONCE(state->ret), 37);
}

static void riscv_setjmp_nested_call_test(struct kunit *test)
{
	struct setjmp_test_state *state;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);
	WRITE_ONCE(state->ret, setjmp(&state->label));
	if (!READ_ONCE(state->jumped)) {
		KUNIT_EXPECT_EQ(test, READ_ONCE(state->ret), 0);
		WRITE_ONCE(state->jumped, 1);
		jump_level_one(test, &state->label);
	}

	KUNIT_EXPECT_EQ(test, READ_ONCE(state->jumped), 1);
	KUNIT_EXPECT_EQ(test, READ_ONCE(state->ret), 73);
}

static struct kunit_case riscv_setjmp_test_cases[] = {
	KUNIT_CASE(riscv_setjmp_zero_value_test),
	KUNIT_CASE(riscv_setjmp_nonzero_value_test),
	KUNIT_CASE(riscv_setjmp_nested_call_test),
	{}
};

static struct kunit_suite riscv_setjmp_test_suite = {
	.name = "riscv-setjmp",
	.test_cases = riscv_setjmp_test_cases,
};

kunit_test_suite(riscv_setjmp_test_suite);

MODULE_DESCRIPTION("KUnit tests for RISC-V setjmp and longjmp");
MODULE_LICENSE("GPL");
