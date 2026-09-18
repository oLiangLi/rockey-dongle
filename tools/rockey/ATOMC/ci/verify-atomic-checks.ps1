# verify-atomic-checks.ps1 —— 用**本机 MSVC** 在宿主上真跑 atomic/tests 的可运行检查
#
# 为什么需要它: 另外两个办法都不行 ——
#   ① Cygwin 的 g++/bash 在本机是坏的 (`*** fatal error - CreateFileMapping ..., Win32 error 5.`);
#   ② harness 沙箱禁止"带管道的子进程" (`spawnSync` 默认 stdio=pipe ⇒ EPERM)。
#   MSVC 是原生 Windows 进程, 不经 Cygwin 共享内存, 所以能跑。它**不是** CI 的替代品
#   (CI 用 g++/clang++, 且 `instantiate` 的意义就是"两个编译器各看一遍"), 只是本地快验。
#
# 用法:  pwsh -File tools/rockey/ATOMC/ci/verify-atomic-checks.ps1
# 退出码: 0 = 全部通过; 非 0 = 有失败 (与 stdio/shim 有关的环境问题会打印原因)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
$vs = 'C:\Program Files\Microsoft Visual Studio\2022\Professional'
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "找不到 vcvars64.bat: $vcvars (改本脚本的 `$vs 路径)" }

$tmp = Join-Path $env:TEMP 'atomic-ci-msvc'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

# base 的日志函数在真库里有; 这里给空实现, 好让检查能在**没有 base 库**的宿主上链接
@'
#include <cstdarg>
#include <cstdint>
#include <base/base.h>
rLANGEXPORT void rlLoggingWrite(int, uint32_t, int, const char*, ...) {}
rLANGEXPORT void rlLoggingWriteEx(int, uint32_t, int, const void*, int, const char*, ...) {}
'@ | Set-Content -Path (Join-Path $tmp 'shim.cc') -Encoding UTF8

# gate-exit-compat.cc 自带 rlLoggingWrite 的 stub (它要数日志调用次数) ⇒ 不能再带 shim (会 LNK2005)
$checks = @(
  @{ name = 'exit-gate-map'; shim = $true },
  @{ name = 'interpreter-smoke'; shim = $true },
  @{ name = 'gate-exit-compat'; shim = $false }
)

$failed = 0
foreach ($c in $checks) {
  $exe = Join-Path $tmp ($c.name + '.exe')
  if (Test-Path $exe) { Remove-Item $exe -Force }
  $src = Join-Path $root ('atomic\tests\' + $c.name + '.cc')
  $shim = if ($c.shim) { ' "' + (Join-Path $tmp 'shim.cc') + '"' } else { '' }
  $cmd = '"' + $vcvars + '" >nul 2>&1 && cl /nologo /std:c++17 /EHsc /W3 "' + $src + '"' + $shim +
         ' /I"' + $root + '" /I"' + (Join-Path $root 'atomic\include') + '"' +
         ' /Fo:"' + $tmp + '\\"' + ' /Fe:"' + $exe + '" /link legacy_stdio_definitions.lib 2>&1'
  $out = cmd.exe /c $cmd
  $errs = $out | Select-String -Pattern 'error C|error LNK'
  if ($errs) {
    Write-Host "[verify] FAIL(编译) $($c.name)"; $errs | Select-Object -First 8 | ForEach-Object { Write-Host "  $($_.Line)" }
    ++$failed; continue
  }
  if (-not (Test-Path $exe)) { Write-Host "[verify] FAIL(未生成) $($c.name)"; ++$failed; continue }
  & $exe | Select-String -Pattern 'FAIL|全部通过|有失败|failures=' | ForEach-Object { Write-Host "  $($_.Line)" }
  $rc = $LASTEXITCODE
  Write-Host "[verify] $(if ($rc -eq 0) { 'PASS' } else { 'FAIL' }) $($c.name) (rc=$rc)"
  if ($rc -ne 0) { ++$failed }
}
exit $failed
