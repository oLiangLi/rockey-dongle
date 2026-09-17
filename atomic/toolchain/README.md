## 相关的信息
- 我们编译器使用 https://github.com/oLiangLi/riscv-gnu-toolchain rLANG-2026.06.06 分支, 基于上游 2026.06.06
- 我们只使用 stage1 的编译结果, 因此 libc/newlib/musl 都不依赖, 只需要编译 binutils + gcc
- 我们**总是**使用 /Machine/ATOMIC/rv32im-atomic-rockey/bin/rv32im-atomic-rockey- 作为 X4C_BUILD_CROSS 前缀
- 编译第三方库时 --target 选riscv32-unknown-elf, 能省非常多的修改配置文件的时间 ...
- 如果我们需要引入一个第三方库, 通常而言我们应该将其编译为HOST版本, 以 op_GATE 的形式调用 ...

