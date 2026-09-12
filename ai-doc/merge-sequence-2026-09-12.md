# 合并序列 —— base/Build submodule 化 + tools 世界分区 + 上游修复(2026-09-12)

> 目标分支:`feat/AGINX/upstream-base-shims` ⇒ 按既有约定以 **squash** 方式落到 `master`,再**只推 `origin`(内网)**。
> 本文件是执行清单:每步给出**判定标准**,不达标就停下。
> 快照仅作参考,权威值用文中给出的命令现取:写作时分支相对 `origin/master` **20 条提交**、净变化 **73 文件(+327 / −15352)**。

## 0. 执行前状态(2026-09-12 核对)

| 项 | 值 |
| --- | --- |
| 合并基准 | 本地 `master` = `6cfa525` **落后** `origin/master` 一个提交(`14edea1`);三远端 master 均已是 `14edea1`(本地 remote-tracking 已 fetch) |
| 待合并提交 | **见 `git rev-list --count origin/master..HEAD`** |
| 分支净变化 | **见 `git diff --stat origin/master...HEAD`**(删 vendored `base/`+`Build/`,换成 2 个 gitlink) |
| 子模块 pin | `base 14a921b` / `Build db0ebfc` —— 内网镜像与 GitHub **均已发布** ✓ |
| hooks | `core.hooksPath=.githooks`;消息以 `Squashed commit of the following:` 开头时 `post-commit` 跑 `make ci`(非阻塞,`CI_SKIP_RUN=1` 跳过) |
| 工作区 | **干净** ✓(WIP 已按步骤 0 提交) |

### 步骤 0 —— 处理工作区 WIP:**已完成 ✓**

`MCU/RockeyARM/rockey_predef.h` 已作为分支提交 **`7713e85`**(`构建: predef 补齐 rlLOGX/rlLOGXX 空宏(设备侧日志全静音)+ 合并前门禁`),
随 squash 一起进 master。该提交同时记录:Windows 侧 `npm ci` 修好 `make jsWrapper`(本地 typescript 5.9.3 / webpack 5.110.3),
以及 `make test-optmatrix` 在 Windows 上的既有 harness 问题(见步骤 2 的"已知例外")。

## 1. 步骤 1 —— 同步 master

```sh
git fetch origin --prune
git checkout master
git merge --ff-only origin/master      # master: 6cfa525 -> 14edea1
```

判定:`git rev-parse --short master` = `14edea1`。

## 2. 步骤 2 —— 合并前门禁:**已完成 ✓**(Windows 侧跑,矩阵在 WSL 跑)

```sh
git checkout feat/AGINX/upstream-base-shims
make jsWrapper            # 需先 npm ci(本地 devDeps: typescript 5.9.3 / webpack 5.110.3)
make windows -j8          # clang-cl 宿主;不应再有 /std:c++17 未使用参数警告
make ci                   # 期望 8/8 PASS: jsuite/mkey/skey/emuadmin/corpus/pkeyself/x509ext/trngfail
make dongle -j8           # 固件 65520 B
make rockey-stack-check   # 栈 <= 2032 B(Windows 实测 1928 B)
make test-web             # 视本机 Chrome 而定, 跳过亦算通过
make test-optmatrix       # 见下"已知例外": 本次在 WSL 跑
```

**实测结果(2026-09-12)**:

| 门禁 | Windows 主工作区 | WSL 交叉验证 |
| --- | --- | --- |
| `make jsWrapper` | rc=0(`npm ci` 后) | rc=0 |
| `make windows -j8` | rc=0 | — |
| `make ci` | **8/8 PASS** | **8/8 PASS** |
| `make dongle -j8` | rc=0,固件 **65520 B**、`.bss` **0x10** | rc=0,固件 **65520 B**、`.text 0xc910`、`.data 0`、`.bss **0x10**` |
| `make rockey-stack-check` | rc=0,**1928 B ≤ 2032 B** | rc=0,**1936 B ≤ 2032 B**(超预算 0 条) |
| `make test-web` | rc=0 | — |
| `make test-optmatrix` | ✗ 既有 harness 问题(见下) | **rc=0,-O0/-O1/-O2/-O3 全 PASS** |

**已知例外(预先存在,与本次改动无关)**:`make test-optmatrix` 在 Windows 上四档全部"构建失败" ——
共享仓 `Build/tools/LIMIT/ci/optmatrix.cjs` 里 `cf = "-DNDEBUG " + opt` **含空格**,Windows 分支走 `shell: true` 时未加引号,
make 于是收到独立的 `-O0` token 并把它当成 `-O`(output-sync)⇒ 报 `不明输出同步类型`;不带 shell 的等价命令 rc=0。
**处理方式(本次采用 ②,已完成 ✓)**:②矩阵门禁在 WSL 侧跑 —— WSL 树先 `git fetch <Windows 检出>` + `git merge --ff-only` 到分支 tip,再 `make test-optmatrix` **rc=0,-O0/-O1/-O2/-O3 全 PASS**(同树另跑 `ci`/`dongle`/`rockey-stack-check` 亦全绿)。
①修 harness(给 `X4C_RELEASE_CFLAGS`/`X4C_RELEASE_CXXFLAGS` 在 `isWin` 时加引号,提交共享 build 仓并更新 pin)留待以后。

**全新克隆冒烟:已完成 ✓** —— `git clone`(本地路径)+ `git checkout feat/AGINX/upstream-base-shims` + `git submodule update --init` **rc=0**,两个子模块精确落在 pin(`base 14a921b` / `Build db0ebfc`),`base/src` 6 文件、`Build/tools/LIMIT/{ci,sbin}` 就位,`make -n dongle|ci|test-optmatrix|jsWrapper` 全 rc=0;`.gitmodules` 保持 GitHub HTTPS URL(经 `insteadOf` 走内网镜像)。

## 3. 步骤 3 —— squash 合并

**方案 A(推荐:主工作树不切走,避免子模块目录被 vendored 文件挡住)**

```sh
git worktree add --detach X:\MyWork\rockey-merge master
# 在 X:\MyWork\rockey-merge 里:
set CI_SKIP_RUN=1                    # 该 worktree 未初始化子模块, 跳过自动 CI
git merge --squash feat/AGINX/upstream-base-shims
git commit -S -F <squash 消息文件>
git branch -f master HEAD            # master 指向该 squash 提交
# 回主工作树:
git worktree remove X:\MyWork\rockey-merge
git checkout master                  # 树内容与分支 tip 完全相同 ⇒ 无痛切换
git submodule update --init
```

**方案 B(传统;需要先清子模块工作目录)**

```sh
git submodule deinit -f base Build   # 必须: 否则切 master 会被子模块里的未跟踪文件挡住
git checkout master
git merge --squash feat/AGINX/upstream-base-shims
git commit -S -F <squash 消息文件>
git submodule update --init
```

squash 提交信息模板(前缀必须一致,否则 hooks 不会触发 CI):

```text
Squashed commit of the following:

base/Build 改为 submodule(pin 上游 evolution)+ tools 世界分区 + 上游修复回灌

- base/Build: 删除自带 vendored 树, 改为 submodule(base 14a921b, Build db0ebfc);
  Makefile/hooks/文档同步, 增加子模块未初始化守卫
- Build: tools/ci -> tools/LIMIT/ci、LIMIT_WORLD 移入本仓 predef、设备编译参数入
  project.local.mk;clang-cl /std:c++17 警告修复;上游 build evolution 见 db0ebfc
- base: C-02(停用自实现 cipher_mem*)、LOGDATA_SIZEMAX 1024->2048 已上游化
- 其他: 工作流约定(主工作区 Windows)、predef 补齐 rlLOGX/rlLOGXX、
  参考检出与相关 scratch 清理
```

判定:`git diff master feat/AGINX/upstream-base-shims` 为**空**(squash 后两者内容必须一致)。

## 4. 步骤 4 —— 合并后验证(在 master)

```sh
git submodule status                 # 两个都是空格前缀, 且等于 pin(无 - / +)
make jsWrapper ; make windows -j8 ; make ci ; make dongle -j8 ; make rockey-stack-check
git show 82112da --stat              # 参考检出清理已落到 master(该提交信息里记有检索关键词)
```

判定:门禁全绿且指标与合并前逐项一致;master 上不再出现指向已删除参考检出的路径。

## 5. 步骤 5 —— 推送(**只推 origin**)

```sh
git push origin master
```

`github` / `gitee` 本次不推(需要时再补:`git push github master`、`git push gitee master`)。
分支本身按 squash 约定不推;要留备份可 `git push origin feat/AGINX/upstream-base-shims`。

## 6. 回滚

- 推送前:`git branch backup-master <旧 master>`,需要时 `git reset --hard backup-master`。
- 推送后:`git revert -m 1 <squash sha>`(子模块 gitlink 也会一并回滚,回滚后需 `git submodule update --init`)。

## 7. 合并之后

- 另一个分支 `doc/AGINX/2026-9-11-rsa-prime-bench`(`1aadd1b`,已推 origin)基于**更早的** master(相对当前 master 有 65 文件差异),
  建议**先 `git rebase master` 再单独 squash**,否则容易冲突。
- WSL 检出本次为交叉验证已同步到分支 tip;之后按约定不主动同步。
- `.bin/` 里若还留着旧的同步 bundle,可直接删(内容是历史重写前的提交)。
- Windows 检出若重装依赖,用 `npm ci`(按 lock,不改 `package-lock.json`)。
