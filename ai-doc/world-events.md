# 世界事件 (World Events)

本文件是世界事件的**唯一说明**;README.md 只保留由工具自动追加的最小章节,逐次事件的历史见 `ai-context.md` 与 git log。

## 它是什么

一种以**提交 hash 为 nonce 的确定性掷骰**:同一个提交在任何机器上都会得到同一结果,因此可离线复算。

    H     = SHA256(commit_hash) 的前 4 个 32-bit 大端字
    Magic = (H[0]*256 + H[1]) & ((1<<kBits) - 1)        // kBits 缺省 18 ⇒ 约 1/262144
    命中  ⇔ Magic == 42

`reserve`(缺省开)下,命中时把 `Annihilus` 的唯一满词缀值 `v = 725` 保留给该次 ⇒ `Perfect() === NaN`("完美"形态)。
术语:**roll(扔骰子)/ sell SoJ(卖乔丹之石)/ 赌博** —— 命中即"出了世界事件"。

## 留痕

命中时写 4 个 console 通道(stdout/stderr 都覆盖)、`.bin/worldevent.log`、`README.md` 与 **git log**(marker 提交);
**只有真的新增了 README 条目才提交**(重复 roll 不产生空提交)。README 里若没有 `## 世界事件 (World Events)` 标记,
工具会**自动补一个最小章节**再追加条目(`Web/Agent/Tests/js/jsWorldEvent.js`)⇒ 精简 README 不会让留痕失效。

## 命令

    roll [kBits] [reserve]                    掷一次
    gamble [max] [kBits] [reserve]            研磨 nonce 直到命中
    soj [<commitish>] [kBits] [noreserve]     记录(写 README + git log)
    worldevent status|audit [kBits] [reserve]|sweep|split
    worldevent sacrifice <三把 K>             见"献祭"
    worldevent cansign <K>                    0=可签名 / 1=禁止

## CI 看门狗

`make ci` 第 9 项 `worldevent(kBits=18, reserve)`:遍历全史,命中 **> 1 次即 FAIL**;命中时回显并自动记录。

## 世界线分裂(完美事件)

完美事件(`Perfect() === NaN`)⇒ 建立两条主世界分支 `world_limit_(YYYY_M_D)_(hash)` 与
`world_atomic_(YYYY_M_D)_(hash)`(时区 +0800,hash = 触发提交);**必须 CI 确认**(`RKEY_WORLDEVENT_CI=1`)。
此时应插入 `E0` / `E10` 之一。当前世界线见 `git branch` 上的 `world_limit_2026_9_14_*` 与 `world_atomic_2026_9_14_*`。

## 献祭(硬分叉)

`worldevent sacrifice K0 K1 K2`(**必须 CI 确认**):被插入的 3 把同时失效,剩下的那把转为**只读**
(此后不能由它签名提交代码);因任意 3 把已覆盖全部 6 个份额,这是一次**硬分叉**,必然产生恰好一个 ATOMIC 世界
(份额表 `K0=ABC`、`K1=ADE`、`K2=BDF`、`K3=CEF`)。状态写 `mkey/SACRIFICE-K.json`
(`RKEY_SACRIFICE_FILE` 可覆盖以演练,`RKEY_WORLDEVENT_DRYRUN=1` 只算不写);守卫 `worldevent cansign`。
