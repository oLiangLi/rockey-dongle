# 调用栈深度检查工具

Cortex-M0 固件的栈预算守门工具。栈区仅 `[0x68000400, 0x68000BF0) = 2032B`
(start.s Vector[0] 设初始 SP, 向下生长到 InOutBuf 顶界), **无 MPU 保护** ——
越界将静默覆写 InOutBuf 的脚本输入区, 不产生任何硬件异常。

任何会加大调用链深度的改动(尤其密码学大栈函数)都应跑一遍本工具。

## 用法

```sh
make dongle          # 先构建固件(生成 .o/.su/.map)
make stack-check     # 检查(等价: node Build/tools/LIMIT/stack-check/stack-check.cjs)
```

退出码: `0` = 无违规, `10` = 存在超预算路径(可接入 CI/钩子)。

常用选项:

```sh
node Build/tools/LIMIT/stack-check/stack-check.cjs [选项] [map文件]
  --budget=N     栈预算(默认 2032)
  --exempt=P,P   豁免终点的函数名模式(默认 OpExecute,OpManager; 空串禁用)
  --top=N        最多显示 N 条违规路径(默认 10)
  --prefix=S     工具链前缀(默认 arm-none-eabi-)
  map文件        默认 .bin/.obj/arm-RockeyARM-native-release/RockeyTrust.map
```

## 原理

1. **帧大小**: 编译期 `-fstack-usage` 产物 `.su` 文件(每函数栈帧字节数)。
2. **调用图**: `objdump -dr` 读取重定位 —— `R_ARM_THM_CALL/R_ARM_CALL` 为调用,
   `R_ARM_THM_JUMP24/R_ARM_JUMP24` 为尾调用(保守地与调用同权重累加, 可能高估)。
   用重定位而非指令解析, 是因为 `-ffunction-sections` 下跨段调用在 .o 中是
   占位符, 真实目标只在重定位行中。虚函数调用已被编译器去虚化为直接 BL
   (已核实), 图是完整的。
3. **分析**: 从 `app_entry` 出发全路径 DFS(带环检测), 求最大深度与超预算路径。
   `.su` 签名(源码类型)与链接符号(c++filt 规范类型)用 "名字( + 参数个数"
   锚定匹配以区分重载。

## 豁免语义(重要)

`OpExecute_*` 与 `OpManager_*` 按**路径终点**豁免, 依据设计:

- `OpExecute_*`: 总在调用栈末尾执行, 执行后程序立即退出 —— 溢出无副作用;
  它们正是为隔离深栈操作而刻意封装的。
- `OpManager_*`: 系统初始化专用, 初始化完成后不再使用, 或运行后改变设备身份,
  运行时不包含敏感信息。

注意是"路径终点"而非"子树豁免": 这些函数的**被调函数**(`Ed25519::Sign`、
`internal_sha512_process` 等)同时被稳态脚本指令(OpEd25519/OpFuncRSA/...)调用,
在那些路径上必须正常计入。输出中的"全量最大深度(含豁免路径)"仅供参考。

## 局限

- 纯静态: 函数指针/回调不可见 —— 本工程 VM 指令派发为直接调用(已核实),
  若未来引入间接派发需人工补充调用边。
- 汇编例程(`__aeabi_*`、libc)无 `.su`, 帧按 0 计并打 `[帧未知]` 标记,
  含此类节点的路径深度是**下界**。
- 环(递归)按首次访问截断, 不展开。

## 历史参考值

| 时点 | 稳态最大深度 | 违规路径 | 说明 |
|---|---|---|---|
| 2026-09-03 修复前 | 2444B | 32 | internal_sha512_process 帧达 1056B(W[80]) |
| W[16] 滚动窗口后 | 2160B | 8 | sha512.cc, 帧 1056→360 |
| Helper 联合体放 Sha512Ctx 后 | 1928B | 0 | curve25519.cc, Sign 592→344 |
| sc_muladd/ge_frombytes noinline 后 | **1784B** | **0** | Sign→40, Verify→224, 余量 248B |
