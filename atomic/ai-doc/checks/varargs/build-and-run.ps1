# build-and-run.ps1 —— 用真 toolchain 编变参测试, 再在我们的 VM_t 上跑起来
#   工具链默认 X:\Machine\ATOMIC\rv32im-atomic-rockey\bin (WSL 侧 /Machine/ATOMIC/...),
#   可用环境变量 $env:RV32IM_TOOLCHAIN 覆盖。宿主编译器用 cygwin g++ (与其它 checks 一致)。
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = (Resolve-Path (Join-Path $here '..\..\..\..')).Path          # -> ATOMIC 仓根
$tc   = if ($env:RV32IM_TOOLCHAIN) { $env:RV32IM_TOOLCHAIN } else { 'X:\Machine\ATOMIC\rv32im-atomic-rockey\bin' }
$gcc  = Join-Path $tc 'riscv32-unknown-elf-gcc.exe'
$od   = Join-Path $tc 'riscv32-unknown-elf-objdump.exe'
if (-not (Test-Path $gcc)) { throw "找不到 RISC-V 工具链: $gcc (用 `$env:RV32IM_TOOLCHAIN 指定)" }

$MARCH = '-march=rv32im', '-mabi=ilp32'

Write-Host "== ① 编 guest (rv32im/ilp32, 裸机, 按 varargs.ld 放在 0x10000) ==" -ForegroundColor Cyan
& $gcc @MARCH -O2 -ffreestanding -nostdlib -nostartfiles -T "$here\varargs.ld" '-Wl,--no-warn-rwx-segments' -o "$here\varargs.elf" "$here\varargs-test.c" -lgcc
if ($LASTEXITCODE) { throw "guest 编译失败" }

Write-Host "== ② 反汇编 (看 prologue / va_start / va_arg 的真实形状) ==" -ForegroundColor Cyan
& $od -d --no-show-raw-insn "$here\varargs.elf" > "$here\varargs.dis"

Write-Host "== ③ 宿主侧跑同一份源码 (对照基准) ==" -ForegroundColor Cyan
& gcc -DHOST_TEST -O2 -o "$env:TEMP\host-va.exe" "$here\varargs-test.c"
& "$env:TEMP\host-va.exe"

Write-Host "== ④ 在我们的解释器上跑 guest ELF ==" -ForegroundColor Cyan
& g++ -std=c++17 -Wall -Werror -I $root -I "$root\atomic\include" -o "$env:TEMP\run-va.exe" "$here\run-varargs.cc"
& "$env:TEMP\run-va.exe" "$here\varargs.elf"
$rc = $LASTEXITCODE
Write-Host ("== 结束: runner rc=$rc (" + $(if ($rc) { '有失败' } else { '全部通过' }) + ") ==") -ForegroundColor $(if ($rc) { 'Red' } else { 'Green' })
exit $rc
