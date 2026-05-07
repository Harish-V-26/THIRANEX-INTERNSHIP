import { useState, useEffect, useRef } from "react";

// ── Crypto helpers ──────────────────────────────────────────────────────────
async function hashPassword(password) {
  const enc = new TextEncoder().encode(password);
  const buf = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Strength engine ─────────────────────────────────────────────────────────
function analyzePassword(pw) {
  const checks = {
    length8: pw.length >= 8,
    length12: pw.length >= 12,
    length16: pw.length >= 16,
    hasLower: /[a-z]/.test(pw),
    hasUpper: /[A-Z]/.test(pw),
    hasDigit: /\d/.test(pw),
    hasSymbol: /[^a-zA-Z0-9]/.test(pw),
    noRepeats: !/(.)(\1{2,})/.test(pw),
    noSequential: !/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(pw),
    noCommon: !["password","123456","qwerty","letmein","admin","welcome","monkey","dragon","master","login"].includes(pw.toLowerCase()),
  };

  const entropy = calcEntropy(pw);
  let score = 0;
  if (checks.length8) score += 10;
  if (checks.length12) score += 15;
  if (checks.length16) score += 10;
  if (checks.hasLower) score += 10;
  if (checks.hasUpper) score += 10;
  if (checks.hasDigit) score += 10;
  if (checks.hasSymbol) score += 15;
  if (checks.noRepeats) score += 10;
  if (checks.noSequential) score += 5;
  if (!checks.noCommon) score = Math.min(score, 15);
  score = Math.min(score, 100);

  let label, color, bg;
  if (score < 25) { label = "Critical"; color = "#ff2d55"; bg = "rgba(255,45,85,0.12)"; }
  else if (score < 50) { label = "Weak"; color = "#ff9f0a"; bg = "rgba(255,159,10,0.12)"; }
  else if (score < 75) { label = "Fair"; color = "#ffd60a"; bg = "rgba(255,214,10,0.12)"; }
  else if (score < 90) { label = "Strong"; color = "#30d158"; bg = "rgba(48,209,88,0.12)"; }
  else { label = "Fortress"; color = "#64d2ff"; bg = "rgba(100,210,255,0.12)"; }

  return { score, label, color, bg, checks, entropy };
}

function calcEntropy(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  if (pool === 0) return 0;
  return Math.floor(pw.length * Math.log2(pool));
}

function crackTime(entropy) {
  // Assumes 10B guesses/sec
  const guesses = Math.pow(2, entropy);
  const secs = guesses / 1e10;
  if (secs < 1) return "Instant";
  if (secs < 60) return `${Math.round(secs)}s`;
  if (secs < 3600) return `${Math.round(secs/60)}m`;
  if (secs < 86400) return `${Math.round(secs/3600)}h`;
  if (secs < 31536000) return `${Math.round(secs/86400)}d`;
  if (secs < 3.154e9) return `${Math.round(secs/31536000)}y`;
  if (secs < 3.154e12) return `${(secs/3.154e9).toFixed(1)}K yrs`;
  return "∞ (heat death)";
}

function generateAlternative(pw) {
  const symbols = "!@#$%^&*";
  const leet = { a: "@", e: "3", i: "1", o: "0", s: "$", t: "7" };
  let alt = pw.split("").map(c => leet[c.toLowerCase()] || c).join("");
  if (!/[A-Z]/.test(alt)) alt = alt.charAt(0).toUpperCase() + alt.slice(1);
  if (!/\d/.test(alt)) alt += Math.floor(Math.random() * 90 + 10);
  if (!/[^a-zA-Z0-9]/.test(alt)) alt += symbols[Math.floor(Math.random() * symbols.length)];
  if (alt.length < 12) alt += symbols[Math.floor(Math.random() * symbols.length)] + Math.floor(Math.random() * 9);
  return alt;
}

function generateRandom(length = 16) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=";
  return Array.from(crypto.getRandomValues(new Uint8Array(length)))
    .map(b => chars[b % chars.length]).join("");
}

// ── Check items ──────────────────────────────────────────────────────────────
const CHECK_META = [
  { key: "length8", label: "At least 8 characters" },
  { key: "length12", label: "At least 12 characters" },
  { key: "length16", label: "At least 16 characters" },
  { key: "hasLower", label: "Lowercase letters" },
  { key: "hasUpper", label: "Uppercase letters" },
  { key: "hasDigit", label: "Numbers" },
  { key: "hasSymbol", label: "Special symbols (!@#$…)" },
  { key: "noRepeats", label: "No repeated characters (aaa…)" },
  { key: "noSequential", label: "No sequential patterns (abc, 123…)" },
  { key: "noCommon", label: "Not a commonly-used password" },
];

// ── Main component ───────────────────────────────────────────────────────────
export default function App() {
  const [pw, setPw] = useState("");
  const [show, setShow] = useState(false);
  const [history, setHistory] = useState([]); // [{hash, label}]
  const [hashed, setHashed] = useState(null);
  const [reuseWarn, setReuseWarn] = useState(false);
  const [copied, setCopied] = useState(null);
  const [altPw, setAltPw] = useState("");
  const inputRef = useRef();

  const analysis = pw ? analyzePassword(pw) : null;

  // Hash + check reuse on every pw change
  useEffect(() => {
    if (!pw) { setHashed(null); setReuseWarn(false); return; }
    hashPassword(pw).then((h) => {
      setHashed(h);
      setReuseWarn(history.some(e => e.hash === h));
    });
  }, [pw, history]);

  // Generate suggestion when pw is typed
  useEffect(() => {
    if (pw.length >= 4) setAltPw(generateAlternative(pw));
    else setAltPw("");
  }, [pw]);

  function saveToHistory() {
    if (!hashed || !analysis) return;
    setHistory(prev => {
      if (prev.some(e => e.hash === hashed)) return prev;
      return [{ hash: hashed, label: analysis.label, short: pw.slice(0, 3) + "•••" }, ...prev].slice(0, 10);
    });
  }

  function copyText(text, id) {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 1800);
  }

  const randomPw = generateRandom();

  return (
    <div style={styles.root}>
      {/* Background grid */}
      <div style={styles.gridBg} />

      <div style={styles.card}>
        {/* Header */}
        <div style={styles.header}>
          <div style={styles.headerIcon}>🔐</div>
          <div>
            <div style={styles.title}>PASSWORD SENTINEL</div>
            <div style={styles.subtitle}>Real-time security analysis & hardening</div>
          </div>
        </div>

        {/* Input */}
        <div style={styles.inputWrap}>
          <input
            ref={inputRef}
            type={show ? "text" : "password"}
            value={pw}
            onChange={e => setPw(e.target.value)}
            placeholder="Enter a password to analyze…"
            style={styles.input}
            autoComplete="off"
            spellCheck={false}
          />
          <button style={styles.eyeBtn} onClick={() => setShow(s => !s)} title="Toggle visibility">
            {show ? "🙈" : "👁"}
          </button>
        </div>

        {/* Reuse warning */}
        {reuseWarn && (
          <div style={styles.reuseAlert}>
            ⚠️ This password was used before — choose a fresh one!
          </div>
        )}

        {/* Meter */}
        {analysis && (
          <>
            <div style={styles.meterRow}>
              <span style={{ ...styles.meterLabel, color: analysis.color }}>{analysis.label}</span>
              <span style={styles.meterScore}>{analysis.score}/100</span>
            </div>
            <div style={styles.meterTrack}>
              <div
                style={{
                  ...styles.meterFill,
                  width: `${analysis.score}%`,
                  background: `linear-gradient(90deg, ${analysis.color}88, ${analysis.color})`,
                  boxShadow: `0 0 12px ${analysis.color}66`,
                }}
              />
            </div>

            {/* Stats row */}
            <div style={styles.statsRow}>
              <StatBadge icon="📏" label="Length" value={pw.length} />
              <StatBadge icon="⚡" label="Entropy" value={`${analysis.entropy} bits`} />
              <StatBadge icon="⏱" label="Crack time" value={crackTime(analysis.entropy)} />
            </div>

            {/* Checks grid */}
            <div style={styles.checksGrid}>
              {CHECK_META.map(({ key, label }) => (
                <CheckItem key={key} pass={analysis.checks[key]} label={label} />
              ))}
            </div>

            {/* Save to history */}
            <button style={styles.saveBtn} onClick={saveToHistory}>
              💾 Save to History
            </button>
          </>
        )}

        {/* Suggestions */}
        {pw.length >= 4 && (
          <div style={styles.suggestSection}>
            <div style={styles.sectionTitle}>💡 Stronger Alternatives</div>

            <SuggestionRow
              label="Hardened version of yours"
              value={altPw}
              id="alt"
              copied={copied}
              onCopy={copyText}
            />
            <SuggestionRow
              label="Random 16-char password"
              value={randomPw}
              id="rand"
              copied={copied}
              onCopy={copyText}
            />
          </div>
        )}

        {/* History */}
        {history.length > 0 && (
          <div style={styles.historySection}>
            <div style={styles.sectionTitle}>🗂 Password History <span style={styles.histNote}>(hashed — never stored in plain text)</span></div>
            <div style={styles.histList}>
              {history.map((e, i) => (
                <div key={i} style={styles.histItem}>
                  <span style={styles.histShort}>{e.short}</span>
                  <span style={styles.histHash}>{e.hash.slice(0, 16)}…</span>
                  <StrengthDot label={e.label} />
                </div>
              ))}
            </div>
            <button style={styles.clearBtn} onClick={() => setHistory([])}>Clear history</button>
          </div>
        )}

        <div style={styles.footer}>
          SHA-256 hashing · client-side only · no data leaves your browser
        </div>
      </div>
    </div>
  );
}

function StatBadge({ icon, label, value }) {
  return (
    <div style={styles.statBadge}>
      <span style={styles.statIcon}>{icon}</span>
      <span style={styles.statLabel}>{label}</span>
      <span style={styles.statValue}>{value}</span>
    </div>
  );
}

function CheckItem({ pass, label }) {
  return (
    <div style={{ ...styles.checkItem, opacity: pass ? 1 : 0.45 }}>
      <span style={{ ...styles.checkIcon, color: pass ? "#30d158" : "#ff2d55" }}>
        {pass ? "✓" : "✗"}
      </span>
      <span style={styles.checkLabel}>{label}</span>
    </div>
  );
}

function SuggestionRow({ label, value, id, copied, onCopy }) {
  return (
    <div style={styles.suggestRow}>
      <div>
        <div style={styles.suggestLabel}>{label}</div>
        <div style={styles.suggestValue}>{value}</div>
      </div>
      <button style={styles.copyBtn} onClick={() => onCopy(value, id)}>
        {copied === id ? "✓ Copied" : "Copy"}
      </button>
    </div>
  );
}

function StrengthDot({ label }) {
  const map = { Critical: "#ff2d55", Weak: "#ff9f0a", Fair: "#ffd60a", Strong: "#30d158", Fortress: "#64d2ff" };
  return (
    <span style={{ ...styles.dot, background: map[label] || "#888" }} title={label} />
  );
}

// ── Styles ───────────────────────────────────────────────────────────────────
const styles = {
  root: {
    minHeight: "100vh",
    background: "#080c14",
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "center",
    padding: "32px 16px 64px",
    fontFamily: "'Courier New', 'Lucida Console', monospace",
    position: "relative",
    overflowX: "hidden",
  },
  gridBg: {
    position: "fixed",
    inset: 0,
    backgroundImage: `
      linear-gradient(rgba(100,210,255,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(100,210,255,0.04) 1px, transparent 1px)
    `,
    backgroundSize: "40px 40px",
    pointerEvents: "none",
  },
  card: {
    width: "100%",
    maxWidth: 640,
    background: "rgba(10,16,30,0.95)",
    border: "1px solid rgba(100,210,255,0.18)",
    borderRadius: 16,
    padding: "32px 28px",
    boxShadow: "0 0 60px rgba(100,210,255,0.06), 0 24px 48px rgba(0,0,0,0.6)",
    position: "relative",
  },
  header: {
    display: "flex",
    alignItems: "center",
    gap: 14,
    marginBottom: 28,
    paddingBottom: 20,
    borderBottom: "1px solid rgba(100,210,255,0.1)",
  },
  headerIcon: { fontSize: 36 },
  title: {
    fontSize: 22,
    fontWeight: 700,
    color: "#64d2ff",
    letterSpacing: "0.12em",
  },
  subtitle: {
    fontSize: 11,
    color: "rgba(100,210,255,0.5)",
    letterSpacing: "0.08em",
    marginTop: 2,
  },
  inputWrap: {
    position: "relative",
    marginBottom: 14,
  },
  input: {
    width: "100%",
    background: "rgba(100,210,255,0.05)",
    border: "1px solid rgba(100,210,255,0.25)",
    borderRadius: 10,
    padding: "14px 48px 14px 16px",
    color: "#e8f4ff",
    fontSize: 16,
    fontFamily: "'Courier New', monospace",
    outline: "none",
    boxSizing: "border-box",
    letterSpacing: "0.05em",
    transition: "border-color 0.2s",
  },
  eyeBtn: {
    position: "absolute",
    right: 12,
    top: "50%",
    transform: "translateY(-50%)",
    background: "none",
    border: "none",
    cursor: "pointer",
    fontSize: 18,
    padding: 4,
  },
  reuseAlert: {
    background: "rgba(255,45,85,0.12)",
    border: "1px solid rgba(255,45,85,0.4)",
    borderRadius: 8,
    padding: "10px 14px",
    color: "#ff6b87",
    fontSize: 13,
    marginBottom: 14,
    letterSpacing: "0.03em",
  },
  meterRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 8,
  },
  meterLabel: {
    fontSize: 14,
    fontWeight: 700,
    letterSpacing: "0.1em",
  },
  meterScore: {
    fontSize: 12,
    color: "rgba(232,244,255,0.4)",
    letterSpacing: "0.06em",
  },
  meterTrack: {
    height: 6,
    background: "rgba(255,255,255,0.07)",
    borderRadius: 99,
    overflow: "hidden",
    marginBottom: 18,
  },
  meterFill: {
    height: "100%",
    borderRadius: 99,
    transition: "width 0.4s cubic-bezier(.4,0,.2,1)",
  },
  statsRow: {
    display: "flex",
    gap: 10,
    marginBottom: 18,
    flexWrap: "wrap",
  },
  statBadge: {
    flex: 1,
    minWidth: 100,
    background: "rgba(100,210,255,0.05)",
    border: "1px solid rgba(100,210,255,0.12)",
    borderRadius: 10,
    padding: "10px 12px",
    display: "flex",
    flexDirection: "column",
    gap: 3,
  },
  statIcon: { fontSize: 16 },
  statLabel: { fontSize: 10, color: "rgba(100,210,255,0.45)", letterSpacing: "0.08em" },
  statValue: { fontSize: 14, color: "#e8f4ff", fontWeight: 600 },
  checksGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: "6px 12px",
    marginBottom: 18,
  },
  checkItem: {
    display: "flex",
    alignItems: "center",
    gap: 7,
    padding: "5px 0",
    transition: "opacity 0.25s",
  },
  checkIcon: { fontSize: 13, fontWeight: 700, flexShrink: 0 },
  checkLabel: { fontSize: 12, color: "rgba(232,244,255,0.7)", letterSpacing: "0.02em" },
  saveBtn: {
    background: "rgba(100,210,255,0.1)",
    border: "1px solid rgba(100,210,255,0.25)",
    borderRadius: 8,
    color: "#64d2ff",
    padding: "9px 18px",
    fontSize: 13,
    cursor: "pointer",
    letterSpacing: "0.06em",
    transition: "background 0.2s",
    marginBottom: 24,
    fontFamily: "'Courier New', monospace",
  },
  suggestSection: {
    borderTop: "1px solid rgba(100,210,255,0.1)",
    paddingTop: 20,
    marginBottom: 20,
  },
  sectionTitle: {
    fontSize: 12,
    color: "rgba(100,210,255,0.6)",
    letterSpacing: "0.1em",
    marginBottom: 12,
    textTransform: "uppercase",
  },
  suggestRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    background: "rgba(48,209,88,0.04)",
    border: "1px solid rgba(48,209,88,0.15)",
    borderRadius: 10,
    padding: "12px 14px",
    marginBottom: 8,
    gap: 10,
  },
  suggestLabel: { fontSize: 10, color: "rgba(48,209,88,0.55)", letterSpacing: "0.07em", marginBottom: 3 },
  suggestValue: { fontSize: 13, color: "#e8f4ff", wordBreak: "break-all", letterSpacing: "0.04em" },
  copyBtn: {
    background: "rgba(48,209,88,0.12)",
    border: "1px solid rgba(48,209,88,0.3)",
    borderRadius: 6,
    color: "#30d158",
    fontSize: 12,
    padding: "6px 12px",
    cursor: "pointer",
    whiteSpace: "nowrap",
    fontFamily: "'Courier New', monospace",
    letterSpacing: "0.05em",
  },
  historySection: {
    borderTop: "1px solid rgba(100,210,255,0.1)",
    paddingTop: 18,
    marginBottom: 8,
  },
  histNote: { fontSize: 10, color: "rgba(100,210,255,0.35)", marginLeft: 6 },
  histList: { display: "flex", flexDirection: "column", gap: 6, marginBottom: 12 },
  histItem: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    background: "rgba(255,255,255,0.03)",
    borderRadius: 8,
    padding: "8px 12px",
    fontSize: 12,
  },
  histShort: { color: "#e8f4ff", minWidth: 50 },
  histHash: { color: "rgba(100,210,255,0.4)", flex: 1, fontFamily: "monospace", letterSpacing: "0.04em" },
  dot: { width: 10, height: 10, borderRadius: "50%", flexShrink: 0 },
  clearBtn: {
    background: "none",
    border: "1px solid rgba(255,45,85,0.3)",
    borderRadius: 6,
    color: "rgba(255,45,85,0.6)",
    fontSize: 11,
    padding: "5px 12px",
    cursor: "pointer",
    fontFamily: "'Courier New', monospace",
    letterSpacing: "0.06em",
  },
  footer: {
    marginTop: 20,
    textAlign: "center",
    fontSize: 10,
    color: "rgba(100,210,255,0.2)",
    letterSpacing: "0.08em",
    borderTop: "1px solid rgba(100,210,255,0.06)",
    paddingTop: 14,
  },
};