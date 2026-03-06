import { useState } from "react";

/* ─── ASCON-AEAD128 BigInt Implementation ─── */
const M64 = (1n << 64n) - 1n;
const NOT = (x) => M64 ^ x;
const ROR = (x, n) => ((x >> n) | (x << (64n - n))) & M64;
const RC = [
  0x3cn, 0x2dn, 0x1en, 0x0fn, 0xf0n, 0xe1n, 0xd2n, 0xc3n,
  0xb4n, 0xa5n, 0x96n, 0x87n, 0x78n, 0x69n, 0x5an, 0x4bn,
];
const AEAD_IV = 0x00001000808c0001n;
const DSEP = 0x8000000000000000n;

function sbox(s) {
  let [a, b, c, d, e] = s;
  a ^= e; e ^= d; c ^= b;
  const t0 = NOT(a) & b;
  const t1 = NOT(b) & c;
  const t2 = NOT(c) & d;
  const t3 = NOT(d) & e;
  const t4 = NOT(e) & a;
  a ^= t1; b ^= t2; c ^= t3; d ^= t4; e ^= t0;
  b ^= a; a ^= e; d ^= c; c = NOT(c);
  return [a, b, c, d, e];
}

function ldiff(s) {
  const [s0, s1, s2, s3, s4] = s;
  return [
    s0 ^ ROR(s0, 19n) ^ ROR(s0, 28n),
    s1 ^ ROR(s1, 61n) ^ ROR(s1, 39n),
    s2 ^ ROR(s2, 1n)  ^ ROR(s2, 6n),
    s3 ^ ROR(s3, 10n) ^ ROR(s3, 17n),
    s4 ^ ROR(s4, 7n)  ^ ROR(s4, 41n),
  ];
}

function runPerm(stIn, rnd) {
  let s = [...stIn];
  const rounds = [];
  for (let i = 0; i < rnd; i++) {
    const ci = RC[16 - rnd + i];
    const before = [...s];
    s = [...s];
    s[2] = s[2] ^ ci;
    const afterC = [...s];
    s = sbox(s);
    const afterS = [...s];
    s = ldiff(s);
    rounds.push({ i, ci, before, afterC, afterS, after: [...s] });
  }
  return { state: s, rounds };
}

const h2b = (h) => {
  const str = h.replace(/[\s:]/g, "");
  return Array.from({ length: Math.floor(str.length / 2) }, (_, i) =>
    parseInt(str.slice(i * 2, i * 2 + 2) || "0", 16)
  );
};
const b2h = (b) => b.map((x) => x.toString(16).padStart(2, "0").toUpperCase()).join("");
const b2w = (b, o = 0) => {
  let w = 0n;
  for (let i = 0; i < 8 && o + i < b.length; i++) {
    w |= BigInt(b[o + i]) << BigInt(8 * i);
  }
  return w;
};
const w2b = (w, n = 8) =>
  Array.from({ length: n }, (_, i) => Number((w >> BigInt(8 * i)) & 0xffn));
const wStr = (w) => w.toString(16).padStart(16, "0").toUpperCase();

function padBlk(bs) {
  const n = bs.length;
  let w0 = 0n;
  let w1 = 0n;
  for (let i = 0; i < Math.min(n, 8); i++) w0 |= BigInt(bs[i]) << BigInt(8 * i);
  for (let i = 8; i < n; i++) w1 |= BigInt(bs[i]) << BigInt(8 * (i - 8));
  if (n < 8) w0 ^= 1n << BigInt(8 * n);
  else if (n === 8) w1 ^= 1n;
  else w1 ^= 1n << BigInt(8 * (n - 8));
  return [w0, w1];
}

function encryptTrace(kHex, nHex, adHex, ptHex) {
  try {
    const KB = h2b(kHex.replace(/\s+/g, "").padEnd(32, "0").slice(0, 32));
    const NB = h2b(nHex.replace(/\s+/g, "").padEnd(32, "0").slice(0, 32));
    const AD = adHex.replace(/\s+/g, "") ? h2b(adHex) : [];
    const PT = ptHex.replace(/\s+/g, "") ? h2b(ptHex) : [];
    const k0 = b2w(KB, 0);
    const k1 = b2w(KB, 8);
    const n0 = b2w(NB, 0);
    const n1 = b2w(NB, 8);
    let s = [AEAD_IV, k0, k1, n0, n1];
    const steps = [];
    const CT = [];

    const push = (phase, label, extra) =>
      steps.push({ phase, label, state: [...s], ...(extra || {}) });

    push("Init", "① Load IV ‖ K ‖ N into state", { initLoad: true });

    const p12i = runPerm(s, 12);
    s = p12i.state;
    push("Init", "② S ← Ascon-p[12](S)", {
      perm: p12i,
      permRnd: 12,
      note: "S ← Ascon-p[12](S) means: apply the permutation with 12 rounds and let the result be the new S — like S = permute(S) in code. Each round: Constant Addition → S-box → Linear Diffusion.",
    });

    const sK = [...s];
    s[3] ^= k0;
    s[4] ^= k1;
    push("Init", "③ S ← S ⊕ (0¹⁹² ‖ K)", {
      prev: sK,
      ch: [false, false, false, true, true],
      note: "XOR key K into the LAST 128 bits of state. Only S[3] and S[4] change — S[0], S[1], S[2] are untouched.",
    });

    if (AD.length > 0) {
      let off = 0;
      let bi = 0;
      while (off <= AD.length) {
        const chunk = AD.slice(off, off + 16);
        const partial = chunk.length < 16;
        const aw = partial ? padBlk(chunk) : [b2w(chunk, 0), b2w(chunk, 8)];
        const aw0 = aw[0];
        const aw1 = aw[1];
        const sA = [...s];
        s[0] ^= aw0;
        s[1] ^= aw1;
        push("AD", "④ Absorb AD block A[" + bi + "] into S[0:127]", {
          prev: sA,
          ch: [true, true, false, false, false],
          blk: { hex: b2h(chunk), w0: aw0, w1: aw1, partial, len: chunk.length },
          note: partial
            ? "Last AD block: " + chunk.length + " byte(s). Padded: Ã‖1‖0^("+  (127 - chunk.length * 8) + "). A 1-bit is appended after data, then zeros fill to 128 bits."
            : "Full 128-bit block XOR'd into S[0] and S[1] (the rate = first 128 bits).",
        });
        const p8 = runPerm(s, 8);
        s = p8.state;
        push("AD", "⑤ S ← Ascon-p[8](S) [after A[" + bi + "]]", {
          perm: p8,
          permRnd: 8,
          note: "Mix the absorbed AD block into the full 320-bit state using 8 rounds.",
        });
        bi++;
        off += 16;
        if (off > AD.length) break;
      }
    }

    const sD = [...s];
    s[4] ^= DSEP;
    push("AD", "⑥ Domain Separation: S[4] ^= 0x8000000000000000", {
      prev: sD,
      ch: [false, false, false, false, true],
      note: "Flip the MSB of S[4]. Marks the boundary between AD and plaintext processing. Even if A and P have identical bytes, the state evolution is completely different after this.",
    });

    const nFull = Math.floor(PT.length / 16);
    for (let i = 0; i < nFull; i++) {
      const chunk = PT.slice(i * 16, i * 16 + 16);
      const pw0 = b2w(chunk, 0);
      const pw1 = b2w(chunk, 8);
      const sP = [...s];
      s[0] ^= pw0;
      s[1] ^= pw1;
      const c = [...w2b(s[0], 8), ...w2b(s[1], 8)];
      CT.push(...c);
      push("Encrypt", "⑦ Encrypt P[" + i + "] → C[" + i + "]", {
        prev: sP,
        ch: [true, true, false, false, false],
        ptB: b2h(chunk),
        ctB: b2h(c),
        note: "S[0:127] ^= P[" + i + "], then C[" + i + "] = S[0:127]. Ciphertext is extracted BEFORE the permutation — streaming design.",
      });
      const p8 = runPerm(s, 8);
      s = p8.state;
      push("Encrypt", "⑧ S ← Ascon-p[8](S) [after P[" + i + "]]", {
        perm: p8,
        permRnd: 8,
        note: "Evolve the state for the next block.",
      });
    }

    const lastPT = PT.slice(nFull * 16);
    const lw = padBlk(lastPT);
    const sL = [...s];
    s[0] ^= lw[0];
    s[1] ^= lw[1];
    const lct =
      lastPT.length === 0
        ? []
        : lastPT.length <= 8
        ? w2b(s[0], lastPT.length)
        : [...w2b(s[0], 8), ...w2b(s[1], lastPT.length - 8)];
    CT.push(...lct);
    push("Encrypt", "⑨ Encrypt last partial block P̃[n] → C̃[n]", {
      prev: sL,
      ch: [true, true, false, false, false],
      ptB: b2h(lastPT),
      ctB: b2h(lct),
      lastPT: true,
      note: "Last block (" + lastPT.length + " bytes) padded then XOR'd. Final C = C[0] ‖ C[1] ‖ … ‖ C[n-1] ‖ C̃[n].",
    });

    const sF = [...s];
    s[2] ^= k0;
    s[3] ^= k1;
    push("Fin", "⑩ S ← S ⊕ (0¹²⁸ ‖ K ‖ 0⁶⁴)", {
      prev: sF,
      ch: [false, false, true, true, false],
      note: "Key K loaded into the MIDDLE of state: S[2] ^= K[0:63] and S[3] ^= K[64:127]. S[0], S[1] and S[4] are unchanged.",
    });

    const p12f = runPerm(s, 12);
    s = p12f.state;
    push("Fin", "⑪ S ← Ascon-p[12](S)", {
      perm: p12f,
      permRnd: 12,
      note: "Final 12-round permutation. Every output bit depends on every input bit — complete diffusion of key, nonce, AD, and plaintext.",
    });

    const tag = [...w2b(s[3] ^ k0, 8), ...w2b(s[4] ^ k1, 8)];
    push("Fin", "⑫ T ← S[192:319] ⊕ K", {
      tag: b2h(tag),
      ct: b2h(CT),
      final: true,
      note: "Tag from the LAST 128 bits (S[3] and S[4] = bits 192–319), XOR'd with K. Returns (C, T).",
    });

    return { ok: true, steps, ct: b2h(CT), tag: b2h(tag) };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/* ─── Design tokens ─── */
const T = {
  bg: "#07090f",
  card: "#0d1117",
  card2: "#111827",
  border: "#1e2535",
  text: "#d4dff0",
  muted: "#4d5e80",
  accent: "#38bdf8",
  Init: "#38bdf8",
  AD: "#4ade80",
  Encrypt: "#fbbf24",
  Fin: "#c084fc",
  chg: "#fb923c",
  chgBg: "rgba(251,146,60,0.12)",
  mono: '"JetBrains Mono","Fira Code","Courier New",monospace',
};

const phColor = (p) => T[p] || T.accent;

/* ─── UI Components ─── */
function Badge({ label, color }) {
  return (
    <span style={{
      fontSize: 9, fontWeight: 800, padding: "3px 8px", borderRadius: 4,
      background: color + "20", color, border: "1px solid " + color + "40",
      letterSpacing: 1.5, textTransform: "uppercase", fontFamily: T.mono,
    }}>
      {label}
    </span>
  );
}

function MathBox({ children, inline }) {
  if (inline) {
    return (
      <code style={{
        background: "#0c1525", border: "1px solid #1e3a5f", borderRadius: 4,
        padding: "1px 7px", fontFamily: T.mono, fontSize: 13, color: "#93c5fd",
      }}>
        {children}
      </code>
    );
  }
  return (
    <div style={{
      background: "#08111e", border: "1px solid #1a3050", borderRadius: 8,
      padding: "14px 20px", fontFamily: T.mono, fontSize: 13, color: "#bfdbfe",
      lineHeight: 2, margin: "10px 0", overflowX: "auto", whiteSpace: "pre",
    }}>
      {children}
    </div>
  );
}

function Callout({ color, icon, title, children }) {
  const c = color || "#38bdf8";
  return (
    <div style={{
      borderLeft: "3px solid " + c, borderRadius: "0 8px 8px 0",
      background: c + "0d", padding: "12px 16px", margin: "12px 0",
    }}>
      {title && (
        <div style={{ color: c, fontWeight: 700, fontSize: 12, marginBottom: 5 }}>
          {icon ? icon + " " : ""}{title}
        </div>
      )}
      <div style={{ fontSize: 13, color: "#9db4cc", lineHeight: 1.75 }}>{children}</div>
    </div>
  );
}

function StateBox({ state, prev, ch }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 2, fontFamily: T.mono, fontSize: 12 }}>
      {state.map((w, i) => {
        const changed = ch ? ch[i] : (prev && prev[i] !== w);
        return (
          <div key={i} style={{
            display: "flex", alignItems: "center", gap: 10,
            padding: "6px 12px", borderRadius: 4,
            background: changed ? T.chgBg : "transparent",
            border: "1px solid " + (changed ? T.chg + "60" : T.border),
          }}>
            <span style={{ color: T.muted, minWidth: 28, fontSize: 10 }}>S[{i}]</span>
            <span style={{ color: changed ? "#fb923c" : T.text, letterSpacing: 0.5, flex: 1 }}>
              0x{wStr(w)}
            </span>
            {changed && prev && (
              <span style={{ color: T.muted, fontSize: 9 }}>← was {wStr(prev[i])}</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

function PermDrill({ perm }) {
  const [rIdx, setRIdx] = useState(0);
  const [sub, setSub] = useState(0);
  const r = perm.rounds[rIdx];
  const subs = [
    { label: "Before", state: r.before, note: "" },
    { label: "After Const.", state: r.afterC, note: "S[2] ^= 0x" + r.ci.toString(16).padStart(2, "0").toUpperCase() + " — breaks round symmetry" },
    { label: "After S-box", state: r.afterS, note: "5-bit SBOX on 64 column positions in parallel — non-linearity" },
    { label: "After Lin. Diff.", state: r.after, note: "Rotate-XOR each word — diffusion, avalanche effect" },
  ];
  const cur = subs[sub];
  return (
    <div style={{ marginTop: 10, border: "1px solid " + T.border, borderRadius: 8, overflow: "hidden" }}>
      <div style={{ background: "#0a0e1a", padding: "8px 12px", borderBottom: "1px solid " + T.border, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={{ color: T.muted, fontSize: 10, fontFamily: T.mono, fontWeight: 700 }}>ROUND</span>
        {perm.rounds.map((_, i) => (
          <button key={i} onClick={() => { setRIdx(i); setSub(0); }} style={{
            padding: "2px 8px", borderRadius: 3, cursor: "pointer",
            border: "1px solid " + (rIdx === i ? T.accent : T.border),
            background: rIdx === i ? T.accent + "20" : "transparent",
            color: rIdx === i ? T.accent : T.muted,
            fontSize: 11, fontFamily: T.mono,
          }}>
            {i}
          </button>
        ))}
      </div>
      <div style={{ padding: 12 }}>
        <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
          {subs.map((s, i) => (
            <button key={i} onClick={() => setSub(i)} style={{
              padding: "5px 12px", borderRadius: 5, cursor: "pointer",
              border: "1px solid " + (sub === i ? T.accent : T.border),
              background: sub === i ? T.accent + "20" : "transparent",
              color: sub === i ? T.accent : T.muted, fontSize: 11,
            }}>
              {s.label}
            </button>
          ))}
        </div>
        {cur.note ? (
          <div style={{ fontSize: 11, color: "#4ade80", marginBottom: 8, fontFamily: T.mono, background: "#0a1a0a", padding: "6px 10px", borderRadius: 4 }}>
            ℹ {cur.note}
          </div>
        ) : null}
        <StateBox state={cur.state} prev={sub > 0 ? subs[sub - 1].state : null} />
      </div>
    </div>
  );
}

function StepDetail({ step }) {
  const [showPerm, setShowPerm] = useState(false);
  if (!step) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: T.muted, fontSize: 13 }}>
        ← Select a step
      </div>
    );
  }
  const pc = phColor(step.phase);
  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%", boxSizing: "border-box" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <Badge label={step.phase} color={pc} />
        <span style={{ color: T.text, fontWeight: 700, fontSize: 15 }}>{step.label}</span>
      </div>
      {step.note ? <Callout color={pc}>{step.note}</Callout> : null}
      {(step.ptB !== undefined || step.ctB !== undefined || step.blk) ? (
        <div style={{ background: T.card2, borderRadius: 6, padding: 12, marginBottom: 12, fontFamily: T.mono, fontSize: 11, border: "1px solid " + T.border }}>
          {step.blk ? (
            <div>
              <div style={{ color: T.muted, marginBottom: 3 }}>AD block: <span style={{ color: "#4ade80" }}>{step.blk.hex || "(empty)"}</span></div>
              <div style={{ color: T.muted, marginBottom: 3 }}>w₀=<span style={{ color: T.text }}>0x{wStr(step.blk.w0)}</span> w₁=<span style={{ color: T.text }}>0x{wStr(step.blk.w1)}</span></div>
              {step.blk.partial ? <div style={{ color: "#fb923c" }}>↳ {step.blk.len} byte(s) + 1-bit padding</div> : null}
            </div>
          ) : null}
          {step.ptB !== undefined ? <div style={{ color: T.muted }}>PT: <span style={{ color: "#fbbf24" }}>{step.ptB || "(empty)"}</span></div> : null}
          {step.ctB !== undefined ? <div style={{ color: T.muted, marginTop: 3 }}>CT: <span style={{ color: T.accent }}>{step.ctB || "(empty)"}</span></div> : null}
        </div>
      ) : null}
      <div style={{ fontSize: 11, color: T.muted, marginBottom: 6, fontWeight: 600, letterSpacing: 0.5 }}>
        STATE AFTER OPERATION
      </div>
      <StateBox state={step.state} prev={step.prev || null} ch={step.ch || null} />
      {step.perm ? (
        <div style={{ marginTop: 14 }}>
          <button onClick={() => setShowPerm((v) => !v)} style={{
            width: "100%", padding: "10px 14px", borderRadius: 6,
            border: "1px solid " + T.accent + "50",
            background: showPerm ? T.accent + "15" : "transparent",
            color: T.accent, cursor: "pointer", fontSize: 12,
            display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
          }}>
            <span>{showPerm ? "▾" : "▸"}</span>
            Drill into Ascon-p[{step.permRnd}] — {step.perm.rounds.length} rounds, 3 layers each
          </button>
          {showPerm ? <PermDrill perm={step.perm} /> : null}
        </div>
      ) : null}
      {step.final ? (
        <div style={{ marginTop: 16, background: "#071510", border: "1px solid #1a4a30", borderRadius: 10, padding: 16 }}>
          <div style={{ color: "#4ade80", fontWeight: 800, fontSize: 13, marginBottom: 12 }}>✓ ENCRYPTION COMPLETE</div>
          <div style={{ fontFamily: T.mono, fontSize: 12, display: "flex", flexDirection: "column", gap: 8 }}>
            <div><span style={{ color: T.muted }}>Ciphertext C:    </span><span style={{ color: T.accent }}>{step.ct || "(empty)"}</span></div>
            <div><span style={{ color: T.muted }}>Tag T (128-bit): </span><span style={{ color: "#c084fc" }}>{step.tag}</span></div>
            <div style={{ borderTop: "1px solid " + T.border, paddingTop: 8, marginTop: 4 }}>
              <span style={{ color: T.muted }}>KAT C‖T: </span>
              <span style={{ color: "#fbbf24", wordBreak: "break-all" }}>{step.ct + step.tag}</span>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

/* ─── Theory Panel ─── */
const SECTIONS = [
  { id: "overview", label: "Overview" },
  { id: "state",    label: "Internal State" },
  { id: "perm",     label: "The Permutation" },
  { id: "init",     label: "Phase 1 · Init" },
  { id: "ad",       label: "Phase 2 · Assoc. Data" },
  { id: "enc",      label: "Phase 3 · Encryption" },
  { id: "fin",      label: "Phase 4 · Finalization" },
  { id: "optional", label: "Optional Features" },
];

function TheorySection({ title, children }) {
  return (
    <div style={{ marginBottom: 56 }}>
      <div style={{ borderBottom: "2px solid " + T.border, paddingBottom: 12, marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: 21, fontWeight: 800, color: T.text }}>{title}</h2>
      </div>
      <div style={{ fontSize: 14, lineHeight: 1.9, color: "#9db4cc" }}>{children}</div>
    </div>
  );
}

function H3({ children, color }) {
  return (
    <h3 style={{
      fontSize: 11, fontWeight: 800, color: color || T.accent,
      letterSpacing: 1.5, textTransform: "uppercase", margin: "22px 0 8px", fontFamily: T.mono,
    }}>
      {children}
    </h3>
  );
}

function Layer({ num, title, color, children }) {
  return (
    <div style={{ border: "1px solid " + color + "30", borderRadius: 10, padding: 18, marginBottom: 14, background: color + "06" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
        <span style={{ background: color + "25", color, fontSize: 11, fontWeight: 800, padding: "3px 10px", borderRadius: 4, fontFamily: T.mono }}>
          LAYER {num}
        </span>
        <span style={{ color, fontWeight: 700, fontSize: 15 }}>{title}</span>
      </div>
      {children}
    </div>
  );
}

function TheoryContent({ sectionId }) {
  if (sectionId === "overview") {
    return (
      <TheorySection title="Overview — What is ASCON-AEAD128?">
        <p style={{ margin: "0 0 14px" }}>
          ASCON-AEAD128 is an <strong style={{ color: T.accent }}>Authenticated Encryption with Associated Data (AEAD)</strong> scheme standardized by NIST in SP 800-232 (August 2025), designed for constrained environments like IoT devices and embedded systems.
        </p>
        <p style={{ margin: "0 0 14px" }}>
          It simultaneously <strong style={{ color: T.text }}>encrypts</strong> secret data and <strong style={{ color: T.text }}>authenticates</strong> all data, so the receiver can verify nothing was tampered with.
        </p>
        <H3>Inputs & Outputs</H3>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, margin: "12px 0" }}>
          <div style={{ background: T.card, border: "1px solid " + T.border, borderRadius: 8, padding: 16 }}>
            <div style={{ color: "#38bdf8", fontSize: 10, fontWeight: 800, marginBottom: 12, letterSpacing: 1.5 }}>INPUTS</div>
            {[["Key K","128 bits","Secret. Never share.","#fbbf24"],["Nonce N","128 bits","Public, unique per message.","#a78bfa"],["Assoc. Data A","variable","Authenticated, not encrypted.","#4ade80"],["Plaintext P","variable","Data to encrypt.","#fb923c"]].map((row) => (
              <div key={row[0]} style={{ marginBottom: 10 }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: row[3], fontFamily: T.mono, fontSize: 12, fontWeight: 700 }}>{row[0]}</span>
                  <span style={{ color: T.text, fontSize: 11, fontFamily: T.mono }}>{row[1]}</span>
                </div>
                <div style={{ color: T.muted, fontSize: 11, marginTop: 1 }}>{row[2]}</div>
              </div>
            ))}
          </div>
          <div style={{ background: T.card, border: "1px solid " + T.border, borderRadius: 8, padding: 16 }}>
            <div style={{ color: "#4ade80", fontSize: 10, fontWeight: 800, marginBottom: 12, letterSpacing: 1.5 }}>OUTPUTS</div>
            {[["Ciphertext C","|C| = |P|","Encrypted plaintext.","#38bdf8"],["Tag T","128 bits","Authentication proof.","#c084fc"]].map((row) => (
              <div key={row[0]} style={{ marginBottom: 10 }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: row[3], fontFamily: T.mono, fontSize: 12, fontWeight: 700 }}>{row[0]}</span>
                  <span style={{ color: T.text, fontSize: 11, fontFamily: T.mono }}>{row[1]}</span>
                </div>
                <div style={{ color: T.muted, fontSize: 11, marginTop: 1 }}>{row[2]}</div>
              </div>
            ))}
          </div>
        </div>
        <Callout color="#fbbf24" icon="⚠️" title="Critical Rule — Never Reuse a Nonce">
          The nonce N must <strong>never</strong> be reused with the same key K. Reuse lets an attacker recover the plaintext. Generate a fresh nonce for every encryption.
        </Callout>
      </TheorySection>
    );
  }

  if (sectionId === "state") {
    return (
      <TheorySection title="Internal State — 320 Bits, 5 Words">
        <p style={{ margin: "0 0 14px" }}>
          Everything in ASCON operates on a single <strong style={{ color: T.text }}>320-bit internal state</strong> — split into 5 words of 64 bits each.
        </p>
        <MathBox>{`S  =  S[0]  ‖  S[1]  ‖  S[2]  ‖  S[3]  ‖  S[4]

  ┌──────────┬──────────┬──────────┬──────────┬──────────┐
  │   S[0]   │   S[1]   │   S[2]   │   S[3]   │   S[4]   │
  └──────────┴──────────┴──────────┴──────────┴──────────┘
   bits 0–63  bits 64–127 bits 128–191 bits 192–255 bits 256–319

  ◄──── Rate (128 bits) ────►◄──── Capacity (192 bits) ──────────►
        S[0] and S[1]              S[2], S[3] and S[4]`}</MathBox>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, margin: "16px 0" }}>
          <Callout color={T.accent} icon="📥" title="Rate = 128 bits  (S[0] and S[1])">
            The <strong>rate</strong> is the number of input bits processed per permutation call. All data is XOR'd into S[0] and S[1]. Ciphertext is extracted from them too.
          </Callout>
          <Callout color="#818cf8" icon="🔒" title="Capacity = 192 bits  (S[2], S[3], S[4])">
            Width (320) − rate (128) = <strong>192 bits</strong>. Never directly exposed — a hidden security buffer.
          </Callout>
        </div>
        <H3>Little-Endian Convention</H3>
        <MathBox>{`Bytes: 0x00  0x01  0x02  …  0x07
    →  S[0] = 0x0706050403020100   (byte 0 = LSB, byte 7 = MSB)`}</MathBox>
      </TheorySection>
    );
  }

  if (sectionId === "perm") {
    return (
      <TheorySection title="The Permutation — Ascon-p[r]">
        <p style={{ margin: "0 0 14px" }}>
          The Ascon permutation is the single core building block — it completely scrambles the 320-bit state. It runs with <MathBox inline>r</MathBox> rounds (8 or 12).
        </p>
        <Callout color="#818cf8" icon="💡" title='What does "S ← Ascon-p[12](S)" mean?'>
          It means: apply the permutation with 12 rounds to the current state S, and let the result be the new S. The arrow ← is just assignment — like <code style={{ fontFamily: T.mono, fontSize: 12 }}>S = permute(S, 12)</code> in code.
        </Callout>
        <H3 color="#fbbf24">Why p[12] vs p[8]?</H3>
        <p style={{ margin: "0 0 14px" }}>
          More rounds = more scrambling = stronger security, but slower. <strong style={{ color: T.text }}>p[12]</strong> is used for initialization and finalization. <strong style={{ color: T.text }}>p[8]</strong> is used for absorbing data.
        </p>
        <H3 color="#fbbf24">3 Layers — Applied Every Single Round</H3>
        <Layer num={1} title="Constant Addition  (p_C)" color="#60a5fa">
          <MathBox>{`S[2]  ^=  c_i          (XOR a unique constant into S[2] each round)

For p[12]: c_0=0x3c c_1=0x2d c_2=0x1e  c_3=0x0f  c_4=0xf0  c_5=0xe1
           c_6=0xd2 c_7=0xc3 c_8=0xb4  c_9=0xa5 c_10=0x96 c_11=0x87

For p[8]:  c_0=0xb4 c_1=0xa5 c_2=0x96  c_3=0x87
           c_4=0x78 c_5=0x69 c_6=0x5a  c_7=0x4b`}</MathBox>
          <p style={{ margin: 0, fontSize: 13, color: "#9db4cc" }}>
            <strong style={{ color: T.text }}>Why?</strong> Without unique constants, every round would be identical — an attacker could exploit that symmetry.
          </p>
        </Layer>
        <Layer num={2} title="Substitution Layer  (p_S) — the S-box" color="#86efac">
          <p style={{ margin: "0 0 10px" }}>Think of the state as a 5×64 matrix. Each of the 64 columns holds 1 bit from each word:</p>
          <MathBox>{`      S[0]:  b₀  b₁  …  b₆₃
      S[1]:  b₀  b₁  …  b₆₃
      S[2]:  b₀  b₁  …  b₆₃
      S[3]:  b₀  b₁  …  b₆₃
      S[4]:  b₀  b₁  …  b₆₃
              ↑   ↑         ↑
           col0 col1 …   col63   ← each column = 5 bits → SBOX → 5 bits`}</MathBox>
          <MathBox>{`Bit-sliced SBOX (x0..x4 = one bit from each word, all 64 cols at once):
  x0^=x4;  x4^=x3;  x2^=x1;
  t0=~x0&x1; t1=~x1&x2; t2=~x2&x3; t3=~x3&x4; t4=~x4&x0;
  x0^=t1; x1^=t2; x2^=t3; x3^=t4; x4^=t0;
  x1^=x0; x0^=x4; x3^=x2; x2=~x2;`}</MathBox>
          <p style={{ margin: 0, fontSize: 13, color: "#9db4cc" }}>
            <strong style={{ color: T.text }}>Why?</strong> Non-linearity. Without it the cipher would be pure XOR and rotations — solvable with linear algebra.
          </p>
        </Layer>
        <Layer num={3} title="Linear Diffusion Layer  (p_L)" color="#fdba74">
          <MathBox>{`S[0]  ←  S[0]  ^  (S[0] >>> 19)  ^  (S[0] >>> 28)
S[1]  ←  S[1]  ^  (S[1] >>> 61)  ^  (S[1] >>> 39)
S[2]  ←  S[2]  ^  (S[2] >>>  1)  ^  (S[2] >>>  6)
S[3]  ←  S[3]  ^  (S[3] >>> 10)  ^  (S[3] >>> 17)
S[4]  ←  S[4]  ^  (S[4] >>>  7)  ^  (S[4] >>> 41)

  >>>  =  right rotation (circular shift)`}</MathBox>
          <p style={{ margin: 0, fontSize: 13, color: "#9db4cc" }}>
            <strong style={{ color: T.text }}>Why?</strong> Diffusion — one bit change spreads everywhere: the avalanche effect.
          </p>
        </Layer>
      </TheorySection>
    );
  }

  if (sectionId === "init") {
    return (
      <TheorySection title="Phase 1 — Initialization">
        <H3>Step 1 — Load IV ‖ K ‖ N</H3>
        <MathBox>{`IV  =  0x00001000808C0001
     (encodes: alg=1, a=12, b=8, tag=128 bits, r/8=16 bytes)

S[0]  ←  IV
S[1]  ←  K[0:63]         (first  8 bytes of key)
S[2]  ←  K[64:127]       (second 8 bytes of key)
S[3]  ←  N[0:63]         (first  8 bytes of nonce)
S[4]  ←  N[64:127]       (second 8 bytes of nonce)`}</MathBox>
        <H3>Step 2 — Apply Ascon-p[12]</H3>
        <MathBox>{"S  ←  Ascon-p[12](S)"}</MathBox>
        <p style={{ margin: "0 0 14px" }}>12 rounds of (Const. Add. → S-box → Lin. Diff.). IV, K, and N are fully mixed — no structural separation remains.</p>
        <H3>Step 3 — XOR key into last 128 bits</H3>
        <MathBox>{`S  ←  S  ⊕  (0¹⁹²  ‖  K)

  S[3]  ^=  K[0:63]       ← bits 192–255  (CHANGED)
  S[4]  ^=  K[64:127]     ← bits 256–319  (CHANGED)
  S[0], S[1], S[2]         ← UNCHANGED`}</MathBox>
        <Callout color={T.Init} icon="🔑" title="Why XOR the key again after the permutation?">
          Feed-forward protection: even if an attacker could invert p[12], they still need K to recover the state. The key is mixed both before and after the scramble.
        </Callout>
      </TheorySection>
    );
  }

  if (sectionId === "ad") {
    return (
      <TheorySection title="Phase 2 — Associated Data Processing">
        <p style={{ margin: "0 0 14px" }}>
          <strong style={{ color: T.text }}>Associated Data (AD)</strong> is authenticated but not encrypted. ASCON mixes it into the state so the final tag covers it.
        </p>
        <Callout color="#4ade80" icon="ℹ️" title="If AD is empty — skip absorption, apply only domain separation." />
        <H3>Parsing and Padding the Last Block</H3>
        <MathBox>{`Parse A into 128-bit blocks:
  A[0],  A[1],  …,  A[m-1],  Ã[m]   (last partial block)

Padding rule — append bit 1 then zeros to reach 128 bits:
  A[m]  =  Ã[m]  ‖  1  ‖  0^(127 − |Ã[m]|)

Examples  (n = byte length of Ã[m]):
  n=0  → byte 0  ^= 0x01
  n=1  → byte 0 = data,    byte 1  ^= 0x01
  n=7  → bytes 0–6 = data, byte 7  ^= 0x01

In code:  state  ^=  (1ULL << (8 * n))`}</MathBox>
        <H3>Absorbing Each Block</H3>
        <MathBox>{`For each block A[i]  (i = 0 to m):
  S[0:127]  ^=  A[i]           ← XOR into rate (S[0] and S[1])
  S         ←  Ascon-p[8](S)   ← mix into full 320-bit state`}</MathBox>
        <H3>Domain Separation</H3>
        <MathBox>{"S[4]  ^=  0x8000000000000000    ← flip the MSB of S[4]"}</MathBox>
        <Callout color="#4ade80" icon="🔀" title="What is domain separation?">
          Flipping S[4]'s MSB marks the boundary between AD and plaintext processing. Even if A and P have identical bytes, the state evolution is completely different after this point.
        </Callout>
      </TheorySection>
    );
  }

  if (sectionId === "enc") {
    return (
      <TheorySection title="Phase 3 — Plaintext Encryption">
        <MathBox>{`Parse P into 128-bit blocks:
  P[0],  P[1],  …,  P[n-1],  P̃[n]   (last partial block)

For each full block P[i]:
  S[0:127]  ^=  P[i]           ← XOR plaintext into rate
  C[i]       =  S[0:127]       ← ciphertext = state AFTER XOR
  S         ←  Ascon-p[8](S)   ← evolve state

For last partial block P̃[n]  (ℓ bits):
  S[0:127]  ^=  pad(P̃[n], 128)  ← same padding as AD
  C̃[n]       =  S[0 : ℓ−1]      ← extract only ℓ bits
  (no permutation after last block)

Final ciphertext:
  C  =  C[0]  ‖  C[1]  ‖  …  ‖  C[n-1]  ‖  C̃[n]`}</MathBox>
        <Callout color="#fbbf24" icon="💡" title="Why is ciphertext extracted BEFORE the permutation?">
          Streaming/online design. C[i] is the XOR of plaintext with the current state — similar to a stream cipher, but with built-in authentication.
        </Callout>
      </TheorySection>
    );
  }

  if (sectionId === "fin") {
    return (
      <TheorySection title="Phase 4 — Finalization & Tag Generation">
        <H3>Step 1 — Load key into middle of state</H3>
        <MathBox>{`S  ←  S  ⊕  (0¹²⁸  ‖  K  ‖  0⁶⁴)

  S[2]  ^=  K[0:63]       ← bits 128–191  (CHANGED)
  S[3]  ^=  K[64:127]     ← bits 192–255  (CHANGED)
  S[0], S[1], S[4]         ← UNCHANGED`}</MathBox>
        <H3>Step 2 — Apply Ascon-p[12]</H3>
        <MathBox>{"S  ←  Ascon-p[12](S)"}</MathBox>
        <p style={{ margin: "0 0 14px" }}>12-round full scramble. Every output bit depends on every input bit — complete diffusion.</p>
        <H3>Step 3 — Extract the tag</H3>
        <MathBox>{`T  ←  S[192:319]  ⊕  K

  T[0:63]    =  S[3]  ^  K[0:63]      ← bits 192–255
  T[64:127]  =  S[4]  ^  K[64:127]    ← bits 256–319

return  (C, T)`}</MathBox>
        <Callout color="#c084fc" icon="🏷️" title="Why XOR the key into tag extraction?">
          The key appears in a sandwich: XOR'd in before p[12] AND used in extraction. This prevents length-extension attacks.
        </Callout>
      </TheorySection>
    );
  }

  if (sectionId === "optional") {
    return (
      <TheorySection title="Optional Features">
        <div style={{ fontSize: 17, fontWeight: 700, color: "#a78bfa", marginBottom: 16 }}>4.2.1 — Tag Truncation</div>
        <p style={{ margin: "0 0 14px" }}>Some applications may shorten the tag to λ bits (λ ≤ 128). Only the leftmost λ bits are kept:</p>
        <MathBox>{"T_truncated  =  T[0 : λ−1]"}</MathBox>
        <Callout color="#a78bfa" icon="⚠️" title="Requirements">
          Minimum 32 bits. Tags under 64 bits need careful analysis. Tag length must stay constant for the key's lifetime. Security strength = λ bits.
        </Callout>
        <div style={{ fontSize: 17, fontWeight: 700, color: "#f472b6", margin: "32px 0 16px" }}>4.2.2 — Nonce Masking</div>
        <p style={{ margin: "0 0 14px" }}>Use a <strong style={{ color: T.text }}>256-bit key K = (K₁ ‖ K₂)</strong>. The nonce is masked with K₂ before encryption:</p>
        <MathBox>{`K  =  K₁  ‖  K₂       (256 bits,  |K₁| = |K₂| = 128 bits)

Encryption:
  E(K₁‖K₂, N, A, P)     =  Ascon-AEAD128.enc( K₁,  N ⊕ K₂,  A, P )

Decryption:
  D(K₁‖K₂, N, A, C, T)  =  Ascon-AEAD128.dec( K₁,  N ⊕ K₂,  A, C, T )

The algorithm runs exactly as normal — the only change is
the nonce passed to it is  N ⊕ K₂  instead of plain N.`}</MathBox>
        <Callout color="#4ade80" icon="✓" title="Benefit — Full 128-bit security in multi-key settings">
          Without nonce masking, u keys give (128 − log₂ u) bits of security. With nonce masking: full 128 bits regardless of how many keys are used.
        </Callout>
        <Callout color="#fb923c" icon="⛔" title="Do NOT use when Context-Commitment Security is required">
          Context-commitment means a ciphertext decrypts under only one specific context. With nonce masking, two different key pairs where N ⊕ K₂ = N′ ⊕ K₂′ produce the same (C, T) — breaking this property.
        </Callout>
        <Callout color="#fb923c" icon="⛔" title="Do NOT use when Related-Key Security is required">
          Nonce masking creates a relationship between K₂ and the effective nonce that a related-key attacker could exploit.
        </Callout>
      </TheorySection>
    );
  }

  return null;
}

function TheoryPanel() {
  const [active, setActive] = useState("overview");
  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden" }}>
      <div style={{ width: 195, flexShrink: 0, borderRight: "1px solid " + T.border, padding: "20px 0", overflowY: "auto", background: "#090d14" }}>
        <div style={{ padding: "0 16px 14px", borderBottom: "1px solid " + T.border, marginBottom: 6 }}>
          <div style={{ fontSize: 9, fontWeight: 800, color: T.muted, letterSpacing: 2, textTransform: "uppercase" }}>Contents</div>
        </div>
        {SECTIONS.map((s) => (
          <div key={s.id} onClick={() => setActive(s.id)} style={{
            padding: "9px 20px", cursor: "pointer", fontSize: 12,
            color: active === s.id ? T.accent : T.muted,
            fontWeight: active === s.id ? 700 : 400,
            borderLeft: "2px solid " + (active === s.id ? T.accent : "transparent"),
            background: active === s.id ? T.accent + "0c" : "transparent",
            transition: "all 0.15s",
          }}>
            {s.label}
          </div>
        ))}
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: "32px 48px 80px" }}>
        <TheoryContent sectionId={active} />
      </div>
    </div>
  );
}

/* ─── Explorer Tab ─── */
function ExplorerTab() {
  const [inputs, setInputs] = useState({
    key: "000102030405060708090A0B0C0D0E0F",
    nonce: "000102030405060708090A0B0C0D0E0F",
    ad: "",
    pt: "",
  });
  const [result, setResult] = useState(null);
  const [cur, setCur] = useState(0);

  const run = () => {
    const r = encryptTrace(inputs.key, inputs.nonce, inputs.ad, inputs.pt);
    setResult(r);
    setCur(0);
  };

  const phGroups = result && result.ok
    ? [...new Set(result.steps.map((s) => s.phase))]
    : [];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      <div style={{ padding: 14, borderBottom: "1px solid " + T.border, background: "#09090f", flexShrink: 0 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
          {[["key","Key K (128-bit hex)"],["nonce","Nonce N (128-bit hex)"],["ad","Associated Data (hex, optional)"],["pt","Plaintext (hex, optional)"]].map((row) => (
            <div key={row[0]}>
              <div style={{ fontSize: 10, color: T.muted, marginBottom: 3, fontWeight: 600, letterSpacing: 0.5 }}>{row[1]}</div>
              <input
                value={inputs[row[0]]}
                onChange={(e) => { const v = e.target.value; setInputs((prev) => ({ ...prev, [row[0]]: v })); }}
                style={{ width: "100%", background: T.card2, border: "1px solid " + T.border, borderRadius: 6, padding: "7px 12px", color: T.text, fontFamily: T.mono, fontSize: 11, outline: "none", boxSizing: "border-box" }}
                spellCheck={false}
              />
            </div>
          ))}
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <button onClick={run} style={{ padding: "8px 22px", borderRadius: 6, background: T.accent, border: "none", color: "#000", fontWeight: 800, cursor: "pointer", fontSize: 12 }}>
            ▶ Encrypt
          </button>
          <button
            onClick={() => setInputs({ key: "000102030405060708090A0B0C0D0E0F", nonce: "101112131415161718191A1B1C1D1E1F", ad: "30313233", pt: "41424344" })}
            style={{ padding: "8px 14px", borderRadius: 6, background: "transparent", border: "1px solid " + T.border, color: T.muted, cursor: "pointer", fontSize: 11 }}
          >
            Load Example
          </button>
          <button
            onClick={() => setInputs({ key: "000102030405060708090A0B0C0D0E0F", nonce: "000102030405060708090A0B0C0D0E0F", ad: "", pt: "" })}
            style={{ padding: "8px 14px", borderRadius: 6, background: "transparent", border: "1px solid " + T.border, color: T.muted, cursor: "pointer", fontSize: 11 }}
          >
            KAT Count=1
          </button>
          {result && result.ok ? (
            <span style={{ fontSize: 11, color: "#4ade80", fontFamily: T.mono }}>
              ✓ {result.steps.length} steps · Tag: {result.tag.slice(0, 16)}…
            </span>
          ) : null}
          {result && result.ok === false ? (
            <span style={{ fontSize: 11, color: "#f87171" }}>Error: {result.error}</span>
          ) : null}
        </div>
      </div>

      {result && result.ok ? (
        <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
          <div style={{ width: 235, flexShrink: 0, overflowY: "auto", borderRight: "1px solid " + T.border, padding: 10, background: "#09090f" }}>
            {phGroups.map((ph) => (
              <div key={ph} style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 9, fontWeight: 800, color: phColor(ph), letterSpacing: 1.5, textTransform: "uppercase", padding: "4px 8px", marginBottom: 4 }}>
                  {ph}
                </div>
                {result.steps.map((s, i) => {
                  if (s.phase !== ph) return null;
                  return (
                    <div key={i} onClick={() => setCur(i)} style={{
                      padding: "6px 10px", borderRadius: 5, cursor: "pointer",
                      fontSize: 11, marginBottom: 2, lineHeight: 1.4,
                      background: cur === i ? phColor(ph) + "18" : "transparent",
                      borderLeft: "2px solid " + (cur === i ? phColor(ph) : T.border),
                      color: cur === i ? phColor(ph) : T.muted,
                    }}>
                      {s.label}
                      {s.perm ? <div style={{ fontSize: 9, color: T.muted, marginTop: 1 }}>↳ p[{s.permRnd}] · {s.perm.rounds.length} rounds</div> : null}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
          <div style={{ flex: 1, overflowY: "auto" }}>
            <StepDetail step={result.steps[cur]} />
          </div>
        </div>
      ) : (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 10 }}>
          <div style={{ fontSize: 28 }}>🔐</div>
          <div style={{ color: T.muted, fontSize: 13 }}>Configure inputs above and click Encrypt to trace the full execution.</div>
        </div>
      )}
    </div>
  );
}

/* ─── Root App ─── */
export default function App() {
  const [tab, setTab] = useState("theory");
  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column", background: T.bg, color: T.text, fontFamily: '"Inter","Segoe UI",system-ui,sans-serif' }}>
      <div style={{ padding: "0 20px", borderBottom: "1px solid " + T.border, background: T.card, display: "flex", alignItems: "center", gap: 20, flexShrink: 0, height: 52 }}>
        <div>
          <span style={{ fontSize: 14, fontWeight: 800, color: T.accent, letterSpacing: 0.5, fontFamily: T.mono }}>ASCON-AEAD128</span>
          <span style={{ fontSize: 10, color: T.muted, marginLeft: 10, letterSpacing: 1 }}>NIST SP 800-232 · Interactive Explorer</span>
        </div>
        <div style={{ display: "flex", gap: 3, marginLeft: "auto" }}>
          {[["theory","📖 Theory"],["explorer","🔬 Cipher Explorer"]].map((row) => (
            <button key={row[0]} onClick={() => setTab(row[0])} style={{
              padding: "6px 16px", borderRadius: 6,
              border: "1px solid " + (tab === row[0] ? T.accent : T.border),
              background: tab === row[0] ? T.accent + "18" : "transparent",
              color: tab === row[0] ? T.accent : T.muted,
              cursor: "pointer", fontSize: 12, fontWeight: tab === row[0] ? 700 : 400,
            }}>
              {row[1]}
            </button>
          ))}
        </div>
      </div>
      <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
        {tab === "theory" ? <TheoryPanel /> : null}
        {tab === "explorer" ? <ExplorerTab /> : null}
      </div>
    </div>
  );
}
