# Lua-LSM RISC-V error-recovery tests

Task 1 has two complementary tests:

- `arch/riscv/kernel/tests/setjmp_kunit.c` directly checks that `setjmp()`
  initially returns zero, `longjmp(label, 0)` returns one, nonzero values are
  preserved, and control is restored through several nested call frames.
- `setjmp_recovery.sh` submits intentional Lua syntax and registration-time
  runtime errors, then registers a valid `file_open` policy. The policy raises
  another runtime error from its hook before the same task invokes the hook
  again, verifying that protected error paths leave both the VM and kernel
  usable.

Enable the RISC-V KUnit suite before building the QEMU kernel:

```sh
scripts/config --file ../out-riscv/.config \
  --enable KUNIT \
  --enable RUNTIME_KERNEL_TESTING_MENU \
  --enable RISCV_SETJMP_KUNIT_TEST
make O=../out-riscv ARCH=riscv olddefconfig
make O=../out-riscv ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- -j4 Image
```

After booting the resulting kernel and mounting `proc`, `sysfs`, and
`securityfs`, run both the boot-time KUnit check and the Lua recovery flow:

```sh
sh setjmp_recovery.sh
```
