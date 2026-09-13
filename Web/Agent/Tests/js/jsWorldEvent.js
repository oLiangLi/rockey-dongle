/*! 以"提交 hash"为 nonce 的确定性 MRND + "完美 (NaN) 世界事件"通知
 *
 * 背景: `base/Web/cipher/jsCipher.ts` 里的 `Annihilus`(暗黑 2 的毁灭小护身符)就是该模块的
 * `WorldEvent`/错误类型; 词缀由一次 `SuperMRND(11*11*6 = 726)` 掷出, 三者全满的唯一马厩值是
 * `v = 725`(1/726); `Perfect()` 还要求 `Magic_ === 42`。两者同时成立才返回 NaN。
 *
 * 约定(2026-09-13 用户给出判据; 完整推导见 ai-context.md 同日条目):
 *   nonce  = 提交的完整 hash
 *   H      = SHA256(nonce) 的前 4 个 32-bit BE 字
 *   Magic  = (H[0]*256 + H[1]) & ((1<<kBits)-1)     // kBits 缺省 18 ⇒ 1/262144 每次提交
 *   MRND   = mulberry32(H[2]^H[3]) 流; 命中 Magic==42 且 reserve 时, v==726 直接给 725
 *            (即"完美词缀保留给 Magic==42 的世界事件" ⇒ Perfect() === NaN)
 *
 * 术语(用户 2026-09-13): 这一行为俗称 **roll / 扔骰子 / sell SoJ(卖乔丹之石) / 赌博**;
 *   命中判据即"出了世界事件"(暗黑 2 里卖 SoJ 到一定数量 ⇒ Uber Diablo 降临) —— 见 `worldevent roll|gamble|soj`。
 *
 * 为什么运行时必须是**有状态流**: `SuperMRND` 同时用于 `localFrame()/localContext()` 的地址
 * 随机化, 同参数返回同一地址会造成别名 ⇒ 不能做成"无状态的 f(v)"。只有 v==726 这一处做特例。
 *
 * nonce 来源(按序): `globalThis.jsCommitWords`(构建预计算, 浏览器用)
 *   → `globalThis.jsCommitHash` → `RKEY_COMMIT_HASH`/`GIT_COMMIT` 环境变量。
 * 拿不到 nonce 时返回 undefined ⇒ 调用方回落到 `CipherLoader` 自带随机(浏览器缺 jsCommitHash.js 时优雅降级)。
 */
(function (root, factory) {
  const api = factory(root);
  root.jsWorldEvent = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  "use strict";

  const kBitsDefault = 18; /** 用户判据; 1/262144 */
  const kStones = "Stones of Jordan Sold to Merchants, Diablo Walks the Earth";

  function splitmix32(x) {
    let z = (x + 0x9e3779b9) | 0;
    z = Math.imul(z ^ (z >>> 16), 0x21f0aaad);
    z = Math.imul(z ^ (z >>> 15), 0x735a2d97);
    return (z ^ (z >>> 15)) >>> 0;
  }

  /** mulberry32: 32-bit 有状态流(用于地址随机化与词缀掷骰) */
  function mulberry32(a) {
    return function () {
      a |= 0;
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return (t ^ (t >>> 14)) >>> 0;
    };
  }

  /** 提交 hash → 4 个 32-bit BE 字(仅 Node: 需要 SHA256) */
  function WordsOf(nonce) {
    let sha = null;
    if (typeof require === "function") {
      try {
        sha = require("crypto");
      } catch (e) {
        sha = null;
      }
    }
    if (!sha) return null;
    const d = sha.createHash("sha256").update(String(nonce)).digest();
    return [d.readUInt32BE(0), d.readUInt32BE(4), d.readUInt32BE(8), d.readUInt32BE(12)];
  }

  /** 由 4 个字构造 MRND 与判据; reserve=true 时把完美词缀保留给 Magic==42 */
  function FromWords(words, nonce, kBits, reserve) {
    if (!words || 4 !== words.length) throw Error("jsWorldEvent: words must be [u32 x4]");
    const k = kBits === undefined ? kBitsDefault : kBits;
    const magic = (words[0] * 256 + words[1]) & ((1 << k) - 1);
    const keepPerfect = false !== reserve && 42 === magic;
    const stream = mulberry32((words[2] ^ words[3]) >>> 0);
    const MRND = (v) => (keepPerfect && 726 === v ? 725 : (stream() >>> 0) % v);
    return {
      nonce: nonce === undefined ? null : String(nonce),
      words: words,
      kBits: k,
      reserve: false !== reserve,
      magic: magic,
      /* trigger: 发生了"世界事件"(判据命中); perfect: 同时满足 Perfect()===NaN */
      trigger: 42 === magic,
      keepPerfect: keepPerfect,
      MRND: MRND,
      perfect: keepPerfect, /* reserve 下: 完美 ⟺ Magic==42 */
    };
  }

  /** 由 nonce 字符串构造(Node 路径) */
  function FromNonce(nonce, kBits, reserve) {
    const words = WordsOf(nonce);
    if (!words) throw Error("jsWorldEvent: SHA256 不可用(浏览器请用 FromWords/jsCommitWords)");
    return FromWords(words, nonce, kBits, reserve);
  }

  /** 当前提交的 nonce(见文件头说明) */
  function CurrentNonce() {
    if (root.jsCommitWords && 4 === root.jsCommitWords.length) return { words: root.jsCommitWords.slice(), nonce: root.jsCommitHash || null };
    if (root.jsCommitHash) return { words: WordsOf(root.jsCommitHash), nonce: root.jsCommitHash };
    const env = typeof process !== "undefined" && process && process.env ? process.env.RKEY_COMMIT_HASH || process.env.GIT_COMMIT : null;
    if (env) return { words: WordsOf(env), nonce: env };
    return null;
  }

  /** Node 侧路径(浏览器返回 null ⇒ 只做 console 通知) */
  function NodePaths() {
    if (typeof require !== "function" || typeof __dirname === "undefined") return null;
    let fs = null,
      path = null;
    try {
      fs = require("fs");
      path = require("path");
    } catch (e) {
      return null;
    }
    const root = path.resolve(__dirname, "..", "..", "..", "..");
    return {
      fs: fs,
      path: path,
      root: root,
      log: path.join(root, ".bin", "worldevent.log"),
      readme: path.join(root, "README.md"),
      marker: "## 世界事件 (World Events)",
    };
  }

  /** 事件行(不限完美): 只要发生了世界事件(roll 出了)就打印/落盘 */
  function Lines(built, note) {
    const p = built.perfect ? "完美" : "非完美";
    built.roll = true; /* roll(扔骰子/sell SoJ/赌博) 的结果 */
    return [
      `${built.perfect ? "☆☆☆" : "☆"} [世界事件] roll(扔骰子/sell SoJ/赌博) 命中: ${p} Annihilus —— ${kStones}`,
      `[世界事件] Magic_=${built.magic} kBits=${built.kBits} reserve=${built.reserve} Perfect()=${built.perfect ? "NaN" : "Infinity"}`,
      `[世界事件] nonce(提交)=${built.nonce || "(precomputed words)"}${note ? `  ${note}` : ""}`,
    ];
  }

  /** 追加进 .bin/worldevent.log 与 README.md 的"世界事件"章节
   *! 幂等: 同一 built 重复调用、或同一 nonce(kBits+reserve 相同)在本进程内重复通知, 都只追加一次;
   *! 另做 README 跨进程去重(同一 nonce 已有条目就不再写, 日志仍逐次追加) */
  function Append(built, lines) {
    const np = NodePaths();
    if (!np) return { log: false, readme: false, skipped: true };
    const key = `${built.nonce}|${built.kBits}|${built.reserve}`;
    if (built.appended || root.jsWorldEvent.__appended.has(key)) return { log: false, readme: false, skipped: true };
    built.appended = true;
    root.jsWorldEvent.__appended.add(key);
    let ok = { log: false, readme: false, skipped: false, dup: false };
    try {
      np.fs.mkdirSync(np.path.dirname(np.log), { recursive: true });
      np.fs.appendFileSync(np.log, `[${new Date().toISOString()}] ${lines.join(" | ")}\n`);
      ok.log = true;
    } catch (e) {
      /* 忽略: 通知失败不影响主流程 */
    }
    try {
      let text = np.fs.existsSync(np.readme) ? np.fs.readFileSync(np.readme, "utf8") : "";
      if (0 > text.indexOf(np.marker)) {
        text += `\n${np.marker}\n\n> 由 Web/Agent/Tests/js/jsWorldEvent.js 自动追加(以提交 hash 为 nonce 的世界事件)。\n\n`;
      }
      /* README 跨进程去重: 同一 nonce 已有条目就不再写(日志仍逐次追加) */
      if (text.includes(`commit \`${built.nonce}\``)) {
        ok.dup = true;
        return ok;
      }
      /* 条目插在"标题 + 其后的说明块(空行/`>` 引用行)"之后, 便于阅读 */
      let at = text.indexOf(np.marker) + np.marker.length;
      const m = /^[ \t]*(?:(?:\r?\n)|(?:>.*(?:\r?\n|$)))*/.exec(text.slice(at));
      at += m ? m[0].length : 0;
      const prefix = 0 < at && "\n" !== text[at - 1] ? "\n" : "";
      const kind = built.trigger ? (built.perfect ? "**完美**" : "非完美") : "未命中(手工记录)";
      const entry = `${prefix}- \`${new Date().toISOString().slice(0, 19)}Z\` ${kind} ` +
        `Annihilus(\`Perfect()=${built.perfect ? "NaN" : "Infinity"}\`) — commit \`${built.nonce || "(precomputed)"}\` ` +
        `Magic_=${built.magic} (kBits=${built.kBits}, reserve=${built.reserve}) — _${kStones}_\n`;
      np.fs.writeFileSync(np.readme, text.slice(0, at) + entry + text.slice(at));
      ok.readme = true;
    } catch (e) {
      /* 忽略 */
    }
    return ok;
  }

  /** 命中通知(不限完美): 四个 console 通道(stdout/stderr 都覆盖) + 日志文件 + README */
  function Notify(built, note) {
    const lines = Lines(built, note);
    const box = ["==================== 世界事件 (World Event) ===================="].concat(lines, [
      "==============================================================",
    ]);
    if (typeof console !== "undefined") {
      console.log(box.join("\n")); /* stdout */
      if (console.info) console.info(lines[0]); /* stdout */
      if (console.warn) console.warn(lines.join("\n")); /* stderr */
      if (console.error) console.error(lines[0]); /* stderr */
    }
    built.notified = (built.notified || 0) + 1;
    const wrote = Append(built, lines);
    return { lines: lines, box: box, wrote: wrote };
  }

  /** 写入 git log: 以提交信息记录世界事件(README 同批提交)
   *! 术语: 这一行为俗称 **roll(扔骰子)/ sell SoJ / 赌博** —— 命中判据即"出了世界事件";
   *! 只有真的新增了 README 条目才提交(重复 roll 不产生空提交) */
  function Record(built) {
    const np = NodePaths();
    const lines = Lines(built, built.note);
    const wrote = built.appended ? { log: false, readme: false, skipped: true } : Append(built, lines);
    const subject = `${built.perfect ? "世界事件(完美)" : "世界事件"} roll: ` +
      `Annihilus Perfect()=${built.perfect ? "NaN" : "Infinity"} ` +
      `commit=${built.nonce || "(precomputed)"} Magic_=${built.magic} (kBits=${built.kBits}, reserve=${built.reserve})`;
    const out = { lines: lines, wrote: wrote, committed: false, subject: subject };
    if (!np) return out;
    if (!wrote.readme) {
      out.skipped = true; /* 已有记录 ⇒ 不再提交, 免得空提交刷屏 */
      if (typeof console !== "undefined") console.log("[世界事件] 该 nonce 已有 README 记录 ⇒ 不重复提交 git log(不重复 roll)");
      return out;
    }
    try {
      const cp = require("child_process");
      cp.execFileSync("git", ["add", "README.md"], { cwd: np.root, stdio: "ignore" });
      cp.execFileSync("git", ["commit", "--no-gpg-sign", "--allow-empty", "-m", subject], { cwd: np.root, stdio: "ignore" });
      out.committed = true;
    } catch (e) {
      out.error = String((e && e.message) || e);
    }
    if (typeof console !== "undefined") {
      const hint = out.committed
        ? "[世界事件] 已写入 git log(见 `git log --oneline -1`)"
        : `[世界事件] 未能写入 git log(${out.error || "unknown"}) —— 可手工: git commit --allow-empty -m "${subject}"`;
      console.log(hint);
      if (console.warn) console.warn(hint);
    }
    return out;
  }

  /** 给 `CipherLoader(TRNG?, MRND?)` 用的 MRND; 拿不到 nonce ⇒ undefined(回落默认随机) */
  function MRNDForCurrentCommit(kBits, reserve) {
    const cur = CurrentNonce();
    if (!cur || !cur.words) return undefined;
    const built = FromWords(cur.words, cur.nonce, kBits, reserve);
    if (built.trigger) {
      /* 发生世界事件(不限完美): 四个 console 通道 + 日志文件 + README */
      Notify(built);
      root.jsWorldEvent.last = built;
    }
    return built.MRND;
  }

  /** 当前提交的判据状态(不触发通知), 供 EmuTests / CI 打印 */
  function Status(kBits, reserve) {
    const cur = CurrentNonce();
    const k = kBits === undefined ? kBitsDefault : kBits;
    if (!cur || !cur.words) {
      return {
        nonce: null,
        magic: null,
        perfect: false,
        kBits: k,
        describe: "commit=<unknown> Magic_=? 完美=? (无 jsCommitWords/jsCommitHash/RKEY_COMMIT_HASH ⇒ CipherLoader 用自带随机)",
      };
    }
    const built = FromWords(cur.words, cur.nonce, k, reserve);
    return Object.assign(built, {
      describe:
        `commit=${built.nonce || "(precomputed words)"} Magic_=${built.magic} ` +
        `kBits=${built.kBits} reserve=${built.reserve} 完美=${built.perfect}${built.perfect ? " ⇒ Perfect()=NaN" : ""}`,
    });
  }

  /**
   * 世界线分裂命名: world_(limit|atomic)_(YYYY_M_D)_(hash hex)
   * stamp 用事件日期, 缺省按项目时区 **UTC+8**(提交都是 +0800; 例如本机 2026-09-13 19:34Z+1 ⇒ 2026_9_14),
   * hash 用触发提交的完整 hex。
   */
  function WorldNames(built, at, tzMinutes) {
    const tz = tzMinutes === undefined ? 480 : tzMinutes; /* +0800 */
    const d = new Date((at || built.at || Date.now()) + tz * 60 * 1000);
    const stamp = `${d.getUTCFullYear()}_${d.getUTCMonth() + 1}_${d.getUTCDate()}`;
    const hash = String(built.nonce || "unknown").replace(/[^0-9a-f]/gi, "").toLowerCase().slice(0, 40);
    return {
      stamp: stamp,
      tzMinutes: tz,
      hash: hash,
      limit: `world_limit_${stamp}_${hash}`,
      atomic: `world_atomic_${stamp}_${hash}`,
    };
  }

  /**
   * 完美世界事件 ⇒ **世界线分裂**: 建立两个主世界分支
   *   world_limit_(YYYY_M_D)_(hash) / world_atomic_(YYYY_M_D)_(hash)
   * 规则(用户 2026-09-13):
   *   - **必须 CI 确认**(RKEY_WORLDEVENT_CI=1 或 opts.ci)才允许分裂;
   *   - 此时应插入 **E0 / E10 之一**(mkey/E0-*、mkey/E10-* 这两把 ukey), 由 CI 确认;
   *   - 插入当代 **3/4 把 K0/K1/K2/K3** 会导致**硬分叉**, 必然产生 **恰好一个** ATOMIC 世界。
   * 幂等: 分支已存在则只记录不重建。
   */
  function Split(built, opts) {
    opts = opts || {};
    const np = NodePaths();
    const names = WorldNames(built, opts.at);
    const out = { names: names, ci: false, created: [], existed: [], perfect: !!built.perfect, refused: null };
    if (!built.perfect) {
      out.refused = "非完美世界事件不分裂世界线(Perfect() 非 NaN)";
      return out;
    }
    const env = typeof process !== "undefined" && process && process.env ? process.env : {};
    const ci = true === opts.ci || "1" === env.RKEY_WORLDEVENT_CI;
    out.ci = ci;
    if (!ci) {
      out.refused = "必须 CI 确认: 设 RKEY_WORLDEVENT_CI=1(或 worldevent split 在 CI 内运行)后再分裂世界线";
      return out;
    }
    if (!np) {
      out.refused = "非 Node 环境";
      return out;
    }
    const cp = require("child_process");
    const start = /^[0-9a-f]{40}$/i.test(String(built.nonce)) ? built.nonce : "HEAD";
    out.start = start;
    for (const b of [names.limit, names.atomic]) {
      try {
        cp.execFileSync("git", ["rev-parse", "--verify", "--quiet", `refs/heads/${b}`], { cwd: np.root, stdio: "ignore" });
        out.existed.push(b);
        continue;
      } catch (e) {
        /* 不存在 ⇒ 创建 */
      }
      try {
        cp.execFileSync("git", ["branch", b, start], { cwd: np.root, stdio: "ignore" });
        out.created.push(b);
      } catch (e) {
        out.error = String((e && e.message) || e);
      }
    }
    return out;
  }

  /** 当代 master ukey 的份额(master.cc: K0=A B C / K1=A D E / K2=B D F / K3=C E F) */
  const K_SHARES = { K0: "ABC", K1: "ADE", K2: "BDF", K3: "CEF" };

  /**
   * 硬分叉判定: 任意 **3 把** K 即覆盖全部 6 个份额(每份额恰属 2 把) ⇒ MASTER.SECRET 可重建 ⇒ 硬分叉,
   * 且**必然产生恰好一个** ATOMIC 世界; 不足 3 把则只覆盖部分份额, 不构成硬分叉。
   */
  function HardFork(keys) {
    const cover = new Set();
    for (const k of keys || []) for (const s of K_SHARES[k] || "") cover.add(s);
    const covered = cover.size;
    const hard = 6 === covered;
    return {
      keys: (keys || []).slice(),
      shares: Array.from(cover).sort().join(""),
      covered: covered,
      hard: hard,
      atomic: hard ? 1 : 0,
    };
  }

  /** 献祭状态文件(跟踪在仓库里): mkey/SACRIFICE-K.json; 可用 RKEY_SACRIFICE_FILE 覆盖(用于演练) */
  function SacrificePath(np) {
    const env = typeof process !== "undefined" && process && process.env ? process.env : {};
    if (env.RKEY_SACRIFICE_FILE) return env.RKEY_SACRIFICE_FILE;
    return np ? np.path.join(np.root, "mkey", "SACRIFICE-K.json") : null;
  }

  function ReadSacrifice(np) {
    const p = SacrificePath(np);
    if (!p || !np.fs.existsSync(p)) return { path: p, events: [] };
    try {
      const j = JSON.parse(np.fs.readFileSync(p, "utf8"));
      if (!Array.isArray(j.events)) j.events = [];
      j.path = p;
      return j;
    } catch (e) {
      return { path: p, events: [], error: String((e && e.message) || e) };
    }
  }

  /**
   * 献祭 3/4 把 K0/K1/K2/K3(必须在完美世界事件之后, 且 **必须 CI 确认**):
   *   - 被插入的 **3 把 ukey 同时失效**(burned);
   *   - **剩下的那把只读**: 对之后所有修改只能读, **不能由 K${X} 签名提交代码**;
   *   - 因为任意 3 把已覆盖全部 6 个份额 ⇒ 同时是一次**硬分叉**, 必然产生恰好一个 ATOMIC 世界。
   * opts: { ci, dryRun, at, worlds, event }
   */
  function Sacrifice(keys, opts) {
    opts = opts || {};
    const np = NodePaths();
    const env = typeof process !== "undefined" && process && process.env ? process.env : {};
    const ci = true === opts.ci || "1" === env.RKEY_WORLDEVENT_CI;
    const dryRun = true === opts.dryRun || "1" === env.RKEY_WORLDEVENT_DRYRUN;
    const list = (keys || []).map((k) => String(k).toUpperCase()).filter((k) => K_SHARES[k]);
    const out = { inserted: list, ci: ci, dryRun: dryRun, refused: null, burned: [], readonly: null, fork: HardFork(list) };
    if (3 !== list.length || 3 !== new Set(list).size) {
      out.refused = `献祭必须是 3/4 把不同的 K0/K1/K2/K3(收到 ${list.length} 把: ${list.join(",") || "无"})`;
      return out;
    }
    if (!ci) {
      out.refused = "必须 CI 确认: 设 RKEY_WORLDEVENT_CI=1 后再执行献祭";
      return out;
    }
    const all = Object.keys(K_SHARES);
    out.burned = list.slice();
    out.readonly = all.filter((k) => 0 > list.indexOf(k))[0] || null;
    out.rule = `${out.burned.join("+")} 失效; ${out.readonly} 只读(可读不可签名提交)`;
    const rec = {
      at: new Date().toISOString(),
      event: opts.event || null,
      worlds: opts.worlds || null,
      inserted: out.burned,
      burned: out.burned,
      readonly: out.readonly,
      shares: out.fork.shares,
      atomic: out.fork.atomic,
    };
    out.record = rec;
    if (dryRun || !np) {
      out.skipped = true;
      return out;
    }
    try {
      const state = ReadSacrifice(np);
      state.events.push(rec);
      const body = JSON.stringify({ events: state.events }, null, 2) + "\n";
      np.fs.writeFileSync(SacrificePath(np), body);
      out.written = SacrificePath(np);
    } catch (e) {
      out.error = String((e && e.message) || e);
    }
    /* 与其它世界事件一致: 留痕到 README + git log —— 仅当确实由**完美事件**触发(献祭是它的后果) */
    const built = opts.built;
    if (built && built.perfect) {
      const lines = [
        `☆☆☆ [世界事件] 献祭(roll 的代价): ${out.burned.join("+")} 失效, ${out.readonly} 转为只读`,
        `[世界事件] 之后所有修改只能读; **不能由 K${out.readonly} 签名提交代码**(必须 CI 确认)`,
        `[世界事件] 份额 ${out.fork.shares}(6/6) ⇒ 硬分叉, ATOMIC=${out.fork.atomic}`,
      ];
      built.note = `献祭 ${out.burned.join("+")} ⇒ ${out.readonly} 只读`;
      Notify(built, built.note);
      Record(built);
    }
    return out;
  }

  /** K 签名守卫: 被献祭的 ukey 失效; 幸存的 ukey 只读 ⇒ **不得由 K${X} 签名提交代码** */
  function CanSign(key) {
    const np = NodePaths();
    const k = String(key || "").toUpperCase();
    const st = ReadSacrifice(np);
    for (const ev of st.events) {
      if ((ev.burned || []).indexOf(k) >= 0) {
        return { key: k, canSign: false, canRead: true, reason: "已献祭失效", event: ev };
      }
      if (ev.readonly === k) {
        return { key: k, canSign: false, canRead: true, reason: "仅只读(禁止 K 签名提交代码)", event: ev };
      }
    }
    return { key: k, canSign: true, canRead: true, reason: "未被献祭", events: st.events.length };
  }

  /*! ─────────────── E0 遗失 / 拾到者签署仪式(用户 2026-09-13) ───────────────
   *! E0(mkey/E0-00000000-f66a164b4c024842)大概率在**敦煌**遗失。拾到 ukey 者需对下列 **UTF-8** 文本做
   *!     Ed25519( SHA512( SHA512( Buffer.from(text) ) ) )
   *! 并在 **git log** 中展示; **每种类型的第一次**暂时创建一个 **ATOMIC**。
   *! 签名者密钥: 缺省用一个**确定性 stand-in**(SHA512("E0-FINDER")[0..32], 便于复现与 CI 验证),
   *! 真拾到者可用 `RKEY_FINDER_SEED` 覆盖为其 ukey 的 Ed25519 私钥。
   *! 四条文本分属 **Type1..Type4**(用户曾误写第 4 条为 Type2, 已更正) ⇒ 每种类型的第一次各创建一个 ATOMIC。
   */
  const FINDER_TEXTS = [
    { type: "Type1", text: "爸爸对不起" },
    { type: "Type2", text: "妈妈我害怕" },
    { type: "Type3", text: "佩佩你已经长大了, 需要努力了" },
    { type: "Type4", text: "沅沅,想我没有" },
  ];

  function FinderDigest(text) {
    const sha = require("crypto");
    const utf8 = Buffer.from(String(text), "utf8");
    const d1 = sha.createHash("sha512").update(utf8).digest();
    const d2 = sha.createHash("sha512").update(d1).digest();
    return { utf8: utf8, digest: d2 };
  }

  function FinderSeed(seed) {
    const sha = require("crypto");
    const s = seed || (typeof process !== "undefined" && process && process.env ? process.env.RKEY_FINDER_SEED : null) || "E0-FINDER";
    return sha.createHash("sha512").update(String(s)).digest().subarray(0, 32);
  }

  /** 逐条签名(Ed25519 对 double-SHA512 摘要)+ 自检验签 */
  function FinderSign(cipher, opts) {
    opts = opts || {};
    const items = opts.texts || FINDER_TEXTS;
    const seed = FinderSeed(opts.seed);
    const ed = cipher.Ed25519().SetPrivateKey(seed);
    const pubkey = ed.GetPublicKey();
    const out = { seedSource: opts.seed ? "explicit" : "default/RKEY_FINDER_SEED", pubkey: pubkey.toString("hex"), items: [] };
    for (const it of items) {
      const d = FinderDigest(it.text);
      const sig = ed.Sign(d.digest);
      out.items.push({
        type: it.type,
        text: it.text,
        utf8: d.utf8.toString("hex"),
        digest: d.digest.toString("hex"),
        signature: Buffer.from(sig).toString("hex"),
        verify: ed.Verify(d.digest, sig),
      });
    }
    out.ok = out.items.every((x) => x.verify);
    return out;
  }

  /** 重新派生 stand-in 公钥并逐条验签(CI 用) */
  function FinderVerify(cipher, record) {
    const seed = FinderSeed(record && record.seed);
    const ed = cipher.Ed25519().SetPrivateKey(seed);
    const pubkey = ed.GetPublicKey().toString("hex");
    const res = { pubkey: pubkey, pubkeyMatch: !record || pubkey === record.pubkey, bad: [] };
    for (const it of (record && record.items) || []) {
      const d = FinderDigest(it.text);
      const okSig = ed.Verify(d.digest, Buffer.from(it.signature, "hex"));
      const okDigest = d.digest.toString("hex") === it.digest;
      const okUtf8 = d.utf8.toString("hex") === it.utf8;
      if (!(okSig && okDigest && okUtf8)) res.bad.push({ type: it.type, text: it.text, okSig: okSig, okDigest: okDigest, okUtf8: okUtf8 });
    }
    res.ok = res.pubkeyMatch && 0 === res.bad.length && !!(record && record.items && record.items.length);
    return res;
  }

  /** 每种类型的**第一次**暂时创建一个 ATOMIC(建分支 world_atomic_<stamp>_finder_<Type>) */
  function FinderAtomic(record, opts) {
    opts = opts || {};
    const np = NodePaths();
    const names = [];
    const seen = new Set();
    for (const it of (record && record.items) || []) {
      if (seen.has(it.type)) continue; /* 同类型只第一次 */
      seen.add(it.type);
      const d = new Date((opts.at || Date.now()) + 480 * 60 * 1000);
      names.push(`world_atomic_${d.getUTCFullYear()}_${d.getUTCMonth() + 1}_${d.getUTCDate()}_finder_${it.type}`);
    }
    const out = { names: names, created: [], existed: [], temporary: true };
    if (opts.dryRun || !np) {
      out.skipped = true;
      return out;
    }
    const cp = require("child_process");
    const start = opts.start || "HEAD";
    for (const b of names) {
      try {
        cp.execFileSync("git", ["rev-parse", "--verify", "--quiet", `refs/heads/${b}`], { cwd: np.root, stdio: "ignore" });
        out.existed.push(b);
        continue;
      } catch (e) {
        /* 不存在 ⇒ 建 */
      }
      try {
        cp.execFileSync("git", ["branch", b, start], { cwd: np.root, stdio: "ignore" });
        out.created.push(b);
      } catch (e) {
        out.error = String((e && e.message) || e);
      }
    }
    return out;
  }

  /**
   * 下一任 K 的编号裁定(用户 2026-09-13): 以每把 ukey 的 **dongle_info 为 nonce** 做一次
   * **Infinity roll**(非完美 ⇒ `Perfect() === Infinity`, 即不触发世界事件), 由综合 digest 落在
   * `[0, N!)` 上选出一种排列 ⇒ 给出 K0..K(N-1) 的指派; **N! 种状态全部列出**便于确认编号
   * (N=4 ⇒ **P(4,4)=24** 种状态)。
   *
   * @param identities [{ id, nonce }] nonce 用 dongle_info 的 40B hex(未初始化/缺失的 ukey 可用
   *                    `{ id, nonce: "ABSENT:<name>" }` 占位, 例如 K4 不参与枚举)
   */
  function Succession(identities, opts) {
    opts = opts || {};
    const kBits = opts.kBits === undefined ? kBitsDefault : opts.kBits;
    const crypto = require("crypto");
    /* 规范化顺序: 设备枚举顺序不稳定 ⇒ 必须按 nonce 排序后再算 digest/排列, 否则每次 rank 都不同 */
    const sorted = identities
      .map((x, i) => ({ i: i, id: x.id || null, nonce: String(x.nonce) }))
      .sort((a, b) => (a.nonce < b.nonce ? -1 : a.nonce > b.nonce ? 1 : 0));
    const N = sorted.length;
    let total = 1;
    for (let i = 2; i <= N; ++i) total *= i;
    const items = sorted.map((x, i) => {
      const nonce = x.nonce;
      const absent = /^ABSENT:/.test(nonce);
      const built = absent ? null : FromNonce(nonce, kBits, true);
      return {
        index: i,
        id: x.id,
        inputIndex: x.i,
        nonce: nonce,
        absent: absent,
        magic: built ? built.magic : null,
        /* Infinity roll: 要求非完美(不触发世界事件) */
        roll: !built ? "(absent)" : built.perfect ? "NaN(完美事件!)" : "Infinity",
        infinity: !built ? false : !built.perfect,
      };
    });
    const digest = crypto.createHash("sha256").update(items.map((x) => x.nonce).join("|")).digest();
    const rank = digest.readUInt32BE(0) % total;
    /* 全部 N! 种排列 + 每种的状态指纹(用于"24 种状态确认编号") */
    const perms = [];
    (function walk(rest, acc) {
      if (!rest.length) {
        perms.push(acc.slice());
        return;
      }
      for (let i = 0; i < rest.length; ++i) walk(rest.filter((_, j) => j !== i), acc.concat([rest[i]]));
    })(items.map((x) => x.index), []);
    const states = perms.map((p, i) => ({
      rank: i,
      order: p,
      state: crypto
        .createHash("sha256")
        .update(`perm=${p.join(">")}|${items.map((x) => x.nonce).join("|")}`)
        .digest("hex"),
    }));
    const chosen = states[rank];
    return {
      N: N,
      total: total,
      kBits: kBits,
      items: items,
      digest: digest.toString("hex"),
      rank: rank,
      chosen: chosen,
      states: states,
      allInfinity: items.filter((x) => !x.absent).every((x) => x.infinity),
      designate: chosen.order.map((idx, k) => ({ K: "K" + k, id: items[idx].id, nonce: items[idx].nonce, absent: items[idx].absent })),
    };
  }

  /** 校验已记录的裁定(CI 用): 重算 rank、检查 N! 种状态齐备且唯一、Infinity roll 成立 */
  function SuccessionVerify(record) {
    const out = { ok: false, reason: null };
    if (!record || !Array.isArray(record.items)) {
      out.reason = "记录缺少 items";
      return out;
    }
    const again = Succession(
      record.items.map((x) => ({ id: x.id, nonce: x.nonce })),
      { kBits: record.kBits },
    );
    out.total = again.total;
    out.rankMatch = again.rank === record.rank;
    out.digestMatch = again.digest === record.digest;
    out.statesCount = again.states.length;
    out.statesComplete = again.states.length === again.total;
    out.statesUnique = new Set(again.states.map((s) => s.state)).size === again.states.length;
    out.infinities = again.allInfinity;
    out.orderMatch = JSON.stringify(again.chosen.order) === JSON.stringify(record.chosen && record.chosen.order);
    out.ok =
      out.rankMatch && out.digestMatch && out.statesComplete && out.statesUnique && out.infinities && out.orderMatch;
    if (!out.ok) out.reason = JSON.stringify(out);
    return out;
  }

  /**
   * 历史审计: 逐个提交算判据。reserve 下"完美事件数 = Magic==42 的提交数"。
   * @returns {{total:number, magic:number, perfect:number, hits:string[]}}
   */
  function Audit(hashes, kBits, reserve) {
    let magic = 0,
      perfect = 0;
    const hits = [];
    for (const h of hashes) {
      const built = FromNonce(h, kBits, reserve);
      if (built.trigger) {
        ++magic;
        if (built.perfect) ++perfect;
        hits.push(h);
      }
    }
    return { total: hashes.length, magic: magic, perfect: perfect, hits: hits };
  }

  return {
    kBitsDefault: kBitsDefault,
    kStones: kStones,
    splitmix32: splitmix32,
    mulberry32: mulberry32,
    WordsOf: WordsOf,
    FromWords: FromWords,
    FromNonce: FromNonce,
    CurrentNonce: CurrentNonce,
    MRNDForCurrentCommit: MRNDForCurrentCommit,
    Status: Status,
    Notify: Notify,
    Record: Record,
    Lines: Lines,
    Append: Append,
    Audit: Audit,
    WorldNames: WorldNames,
    Split: Split,
    HardFork: HardFork,
    K_SHARES: K_SHARES,
    Sacrifice: Sacrifice,
    CanSign: CanSign,
    FINDER_TEXTS: FINDER_TEXTS,
    FinderDigest: FinderDigest,
    FinderSign: FinderSign,
    FinderVerify: FinderVerify,
    FinderAtomic: FinderAtomic,
    Succession: Succession,
    SuccessionVerify: SuccessionVerify,
    ReadSacrifice: ReadSacrifice,
    SacrificePath: SacrificePath,
    last: null,
    __appended: new Set(),
  };
});
