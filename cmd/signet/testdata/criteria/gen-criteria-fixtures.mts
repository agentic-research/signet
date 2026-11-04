// Generates signet-be49b9's golden fixtures with notme's OWN minting code
// and records notme's OWN verdict (verifyChain, or checkCriteria for an
// authority-issued leaf) for each one in manifest.json. It uses notme
// read-only: it imports notme's modules by absolute path and writes only to
// <outdir>.
//
//   export NOTME_REPO=/abs/path/to/notme   # with node_modules installed
//   "$NOTME_REPO/node_modules/.bin/tsx" gen-criteria-fixtures.mts <outdir>
//
// Then copy <outdir>/*.pem here as *.cert (the repo ignores *.pem), along
// with manifest.json. The @peculiar/x509 path below names the version
// notme's lockfile pins. Update it if that version changes.
const NOTME = process.env.NOTME_REPO;
if (!NOTME) throw new Error("set NOTME_REPO to a notme checkout");

// Pin the clock so every fixture is valid at T0 and lifetimes are exact.
const T0 = new Date("2026-11-04T12:00:00Z").getTime();
const RealDate = Date;
class FixedDate extends RealDate {
  constructor(...a: any[]) {
    if (a.length === 0) super(T0);
    else super(...(a as [any]));
  }
  static now() {
    return T0;
  }
}
(globalThis as any).Date = FixedDate;

const { mkdirSync, writeFileSync } = await import("node:fs");
const { join } = await import("node:path");
const ca = await import(`${NOTME}/worker/src/cert-authority.ts`);
const crit = await import(`${NOTME}/worker/src/criteria.ts`);
const lib = await import(`${NOTME}/scripts/task-cert/lib.ts`);
const { ED25519 } = await import(`${NOTME}/worker/src/platform.ts`);
// The same module instance notme's code resolves (no exports map: "main").
const P = await import(`${NOTME}/node_modules/.pnpm/@peculiar+x509@1.14.3/node_modules/@peculiar/x509/build/x509.cjs.js`);
const { X509Certificate, X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags, Extension } = P as any;

const OUT = process.argv[2]!;
mkdirSync(OUT, { recursive: true });

const ROOT_NAME = "CN=signet-authority,O=notme";
const AS = { name: "agent-session", version: 1 };
const LLO = { name: "llo-run", version: 1 };
const DEP = { name: "deploy", version: 1 };
const MYSTERY = { name: "mystery", version: 3 };

const root = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
const rootCert = await X509CertificateGenerator.createSelfSigned({
  name: ROOT_NAME,
  notBefore: new Date(T0 - 86_400_000),
  notAfter: new Date(T0 + 86_400_000 * 365),
  signingAlgorithm: ED25519,
  keys: root,
  serialNumber: "01",
  extensions: [
    new BasicConstraintsExtension(true, 1, true),
    new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
  ],
});
const rootPem: string = rootCert.toString("pem");
writeFileSync(join(OUT, "root.pem"), lib.pemChain(rootPem));

// ONE tier key, several tier certificates for it (same subject, same key),
// differing only in .1.10. A task signed by the key chains under any of them,
// which is how a real notme-minted task is shown against a tier it was not
// minted under (the stripped-.1.10 control, a grant mismatch).
const tierKey = await lib.generateTierKey();
async function tier(criteria?: any[]) {
  const r = await ca.mintIssuingCaCert("alice", "wimse://notme.bot/principal/alice", tierKey.pem, root.privateKey, {
    scopes: ["bridgeCert", "sign:git", "certMint"],
    epoch: 3,
    authMethod: "passkey",
    criteria,
  });
  return r.certificate as string;
}
const tiers: Record<string, string> = {
  as: await tier([AS]),
  legacy: await tier(),
  llo: await tier([LLO]),
  dep: await tier([DEP]),
  multi: await tier([AS, LLO]),
  mystery: await tier([MYSTERY]),
};

async function keysPem() {
  const pemWrap = (der: Uint8Array) =>
    `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...der)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----\n`;
  const m = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const s = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  return {
    mtls: pemWrap(new Uint8Array((await crypto.subtle.exportKey("spki", m.publicKey)) as ArrayBuffer)),
    signing: pemWrap(new Uint8Array((await crypto.subtle.exportKey("spki", s.publicKey)) as ArrayBuffer)),
  };
}

const goal = "0".repeat(64);
const taskScopeDer = (task: string) => {
  const hash = new Uint8Array(32);
  return ca.derTlv(0x30, new Uint8Array([...ca.derUtf8String(task), ...ca.derTlv(0x04, hash)]));
};
const OID_TASK_SCOPE = "1.3.6.1.4.1.99999.1.9";

// notme's lower-level minter, bypassing mintTaskCertPair's mint-time checks:
// the exact certificate shape a misbehaving minter would emit.
async function forged(opts: {
  signer: "tier" | "root";
  criteriaDer?: Uint8Array;
  scopes?: string[];
  ttlS?: number;
  confinement?: boolean;
  task?: string;
}) {
  const k = await keysPem();
  const task = opts.task ?? "forged-task";
  const issuer = opts.signer === "tier" ? new X509Certificate(tiers.as).subject : ROOT_NAME;
  const signingKey = opts.signer === "tier" ? tierKey.privateKey : root.privateKey;
  const identity =
    opts.signer === "tier" ? `wimse://notme.bot/principal/alice/${task}` : "wimse://notme.bot/deploy/alice";
  const extra: any[] = [];
  if (opts.signer === "tier") extra.push(new Extension(OID_TASK_SCOPE, false, taskScopeDer(task)));
  if (opts.criteriaDer) extra.push(new Extension(ca.OID_CRITERIA, false, opts.criteriaDer));
  if (opts.confinement) extra.push(new Extension("1.3.6.1.4.1.99999.1.7", false, ca.derTlv(0x04, new Uint8Array(32))));
  const r = await ca.mintBridgeCertPair(task, identity, k.mtls, k.signing, signingKey, {
    scopes: opts.scopes ?? ["bridgeCert"],
    epoch: 3,
    authMethod: "passkey",
    ttlMs: (opts.ttlS ?? 300) * 1000,
    issuerName: issuer,
    principalKind: "agent",
    extraExtensions: extra,
  });
  return r.certificates.mtls as string;
}

async function real(tierName: string, criteria?: string, task = "rosary-056d96") {
  const t = await lib.mintTask(tiers[tierName]!, tierKey.privateKey, { task, goal: "dispatch identity", epoch: 3, criteria });
  return t.certificates.mtls as string;
}

type Case = { name: string; leaf: string; tier: string | null; cutoff?: string; how: string };
const cases: Case[] = [
  { name: "agent-session-ok", leaf: await real("as"), tier: "as", how: "mintTask under a tier granting agent-session/1" },
  { name: "multi-grant-ok", leaf: await real("multi", "agent-session/1"), tier: "multi", how: "mintTask --criteria agent-session/1 under a tier granting agent-session/1 and llo-run/1" },
  { name: "legacy-ok", leaf: await real("legacy"), tier: "legacy", how: "mintTask under a pre-criteria tier, no cutoff" },
  { name: "legacy-before-cutoff", leaf: await real("legacy"), tier: "legacy", cutoff: "2026-12-01", how: "legacy, cutoff after T0" },
  { name: "legacy-past-cutoff", leaf: await real("legacy"), tier: "legacy", cutoff: "2026-11-01T00:00:00Z", how: "legacy, cutoff before T0" },
  { name: "tier-criteria-task-none", leaf: await real("legacy"), tier: "as", how: "stripped-.1.10 control: a real legacy task shown with an agent-session/1 tier of the same key" },
  { name: "not-granted", leaf: await real("as"), tier: "llo", how: "a real agent-session/1 task shown with an llo-run/1 tier of the same key" },
  { name: "task-claims-without-tier", leaf: await real("as"), tier: "legacy", how: "a real agent-session/1 task shown with a pre-criteria tier of the same key" },
  { name: "lifetime-300-ok", leaf: await forged({ signer: "tier", criteriaDer: crit.encodeCriteria([AS]), ttlS: 300 }), tier: "as", how: "mintBridgeCertPair, agent-session/1, 300 s" },
  { name: "lifetime-over", leaf: await forged({ signer: "tier", criteriaDer: crit.encodeCriteria([AS]), ttlS: 301 }), tier: "as", how: "mintBridgeCertPair, agent-session/1, 301 s" },
  { name: "scope-over", leaf: await forged({ signer: "tier", criteriaDer: crit.encodeCriteria([AS]), scopes: ["bridgeCert", "certMint"] }), tier: "as", how: "mintBridgeCertPair, agent-session/1, scope certMint" },
  { name: "scope-sign-git-ok", leaf: await forged({ signer: "tier", criteriaDer: crit.encodeCriteria([AS]), scopes: ["bridgeCert", "sign:git"] }), tier: "as", how: "mintBridgeCertPair, agent-session/1, sign:git within the ceiling" },
  { name: "llo-run-no-digest", leaf: await forged({ signer: "tier", criteriaDer: crit.encodeCriteria([LLO]) }), tier: "llo", how: "mintBridgeCertPair, llo-run/1 without .1.7 (not mintable)" },
  { name: "llo-run-scope-over", leaf: await forged({ signer: "tier", criteriaDer: crit.encodeCriteria([LLO]), scopes: ["bridgeCert", "sign:git"], confinement: true }), tier: "llo", how: "mintBridgeCertPair, llo-run/1 with sign:git" },
  { name: "deploy-under-tier", leaf: await forged({ signer: "tier", criteriaDer: crit.encodeCriteria([DEP]) }), tier: "dep", how: "mintBridgeCertPair, deploy/1 signed by a tier" },
  { name: "deploy-authority-ok", leaf: await forged({ signer: "root", criteriaDer: crit.encodeCriteria([DEP]), ttlS: 900 }), tier: null, how: "mintBridgeCertPair, deploy/1 signed by the root, 900 s" },
  { name: "deploy-authority-too-long", leaf: await forged({ signer: "root", criteriaDer: crit.encodeCriteria([DEP]), ttlS: 10800 }), tier: null, how: "mintBridgeCertPair, deploy/1 signed by the root, 3 h" },
  { name: "agent-session-from-root", leaf: await forged({ signer: "root", criteriaDer: crit.encodeCriteria([AS]) }), tier: null, how: "mintBridgeCertPair, agent-session/1 signed by the root" },
  { name: "unknown-criteria", leaf: await forged({ signer: "tier", criteriaDer: crit.encodeCriteria([MYSTERY]) }), tier: "mystery", how: "mintBridgeCertPair, mystery/3 under a mystery/3 tier" },
  { name: "malformed-leaf", leaf: await forged({ signer: "tier", criteriaDer: ca.derTlv(0x30, new Uint8Array()) }), tier: "as", how: "mintBridgeCertPair, .1.10 = empty SEQUENCE" },
  { name: "two-on-task", leaf: await forged({ signer: "tier", criteriaDer: crit.encodeCriteria([AS, LLO]) }), tier: "multi", how: "mintBridgeCertPair, two criteria on a task" },
];

const manifest: any[] = [];
for (const c of cases) {
  const cutoff = c.cutoff ? lib.parseLegacyCutoff(c.cutoff) : { ok: true, cutoff: undefined };
  if (!cutoff.ok) throw new Error(cutoff.message);
  let verdict: any;
  if (c.tier) {
    verdict = await lib.verifyChain(rootPem, tiers[c.tier]!, c.leaf, new Date(T0), { legacyCutoff: cutoff.cutoff });
  } else {
    // Authority-issued: notme's task-cert verify has no tier to show, so the
    // verdict is checkCriteria's with a null tier.
    const v = crit.checkCriteria(null, new X509Certificate(c.leaf), { at: new Date(T0), legacyCutoff: cutoff.cutoff });
    verdict = v.ok ? { ok: true, criteria: v.criteria ? crit.criteriaId(v.criteria) : null, legacy: v.legacy } : v;
  }
  // notme's own chain.pem writer (task-cert mint).
  const chain = c.tier ? lib.pemChain(c.leaf, tiers[c.tier]!) : lib.pemChain(c.leaf);
  writeFileSync(join(OUT, `${c.name}.pem`), chain);
  manifest.push({ name: c.name, tier: c.tier, cutoff: c.cutoff ?? null, how: c.how, notme: verdict });
}
writeFileSync(
  join(OUT, "manifest.json"),
  JSON.stringify({ generated_by: "notme worker/src/cert-authority.ts + scripts/task-cert/lib.ts", at: new RealDate(T0).toISOString(), cases: manifest }, null, 2) + "\n",
);
console.log(JSON.stringify(manifest.map((m) => [m.name, m.notme]), null, 0));
