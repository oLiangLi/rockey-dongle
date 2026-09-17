##
## TODO: LiangLI, porting musl/tlsf, binding op_GATE for libgcc ...
##


##
##
##
COMMON_CFLAGS := -I$(wORLD_ROOT) -include $(wORLD_ROOT)/atomic/include/_rv32im-atomic-predef.h

##
## musl
##
## 注意顺序: atomic/musl/arch/riscv32 **必须排在** third_party/musl/arch/riscv32 之前 ...
## - atomic_arch.h 是用引号包含的 (#include "atomic_arch.h"), 解析顺序是"包含者目录 -> -I 顺序" ...
## - 我们用 atomic/musl/arch/riscv32/atomic_arch.h 覆盖上游那份
##   (上游的 a_cas 用了 lr.w/sc.w, 需要 A 扩展, 而我们只实现 RV32IM) ...
##
COMMON_CFLAGS +=  \
   -I$(wORLD_ROOT)/third_party/musl/include			\
   -I$(wORLD_ROOT)/atomic/musl/arch/riscv32			\
   -I$(wORLD_ROOT)/third_party/musl/arch/riscv32	\
   -I$(wORLD_ROOT)/third_party/musl/arch/generic	\
   -I$(wORLD_ROOT)/atomic/musl



##
##
##
X4C_COMMON_CFLAGS   += $(COMMON_CFLAGS)
X4C_COMMON_CXXFLAGS += $(COMMON_CFLAGS)
X4C_COMMON_CXXFLAGS += -I$(wORLD_ROOT)/atomic/include/libstdc++/std
