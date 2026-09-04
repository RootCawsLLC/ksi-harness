'use client';

import { useState } from 'react';

/* ---- light client-side mirrors of the tool's shapes (only fields we render) ---- */
type Cov = 'automated' | 'partial' | 'manual' | 'unaddressed' | 'unrouted' | 'not-applicable';
type Ev =
  | 'satisfied-in-part'
  | 'failing'
  | 'degraded'
  | 'no-evidence'
  | 'manual-attested'
  | 'not-evidenced';

interface Population {
  expected?: number;
  examined?: number;
  complete?: boolean;
  decidable?: number;
  source_of_truth?: string;
  enumerated_from?: string;
}
interface CheckState {
  check_id: string;
  present: boolean;
  result: string | null;
  age_days: number | null;
  run_count: number;
  population: Population | null;
  metric: { metric_id: string; value: number; unit: string } | null;
  fixture: boolean;
}
interface Indicator {
  id: string;
  theme: string;
  name: string;
  applicable: boolean;
  optional: boolean;
  coverage: Cov;
  evidence_state: Ev;
  cadence: { claimed: string | null; met: boolean | null; detail: string } | null;
  checks: CheckState[];
  controls: string[];
  unautomated: string[];
  reason: string | null;
  next: string | null;
}
interface Finding {
  indicator: string;
  name: string;
  evidence_state: string;
  checks: { check_id: string; result: string; failing_items: number }[];
}
interface ArtifactOut {
  kind: string;
  label: string;
  validated: boolean;
  bytes?: number;
  error?: string;
  document: unknown | null;
}
interface Counts {
  total: number;
  applicable: number;
  optional: number;
  coverage: Record<string, number>;
  evidence_state: Record<string, number>;
  cadence_unmet: number;
}
interface RunResult {
  ruleset: { version: string; last_updated: string; sha256: string };
  klass: string;
  routesValid: boolean;
  routeErrors: string[];
  counts: Counts;
  evidence: { bundle_count: number; fixture_bundles: number; tampered: unknown[]; chain_breaks: unknown[]; unreadable: unknown[] };
  themes: { short: string; name: string }[];
  indicators: Indicator[];
  findings: Finding[];
  diff: { counts: Record<string, number> } | null;
  artifacts: ArtifactOut[];
  collectFailures: unknown[];
  durationMs: number;
}

const ARTIFACTS = [
  { id: 'sdr', name: 'Security Decision Record', blurb: 'The 20x SDR (KSI section), schema-validated before write.' },
  { id: 'ocr', name: 'Ongoing Certification Report', blurb: 'The quarterly 20x artifact, from the same state.' },
  { id: 'scn', name: 'Significant Change Notification', blurb: 'Which indicators a declared change touches.' },
  { id: 'oscal-ar', name: 'OSCAL Assessment Results', blurb: 'Rev5 projection of the same control state.' },
] as const;

export default function Page() {
  const [selected, setSelected] = useState<Record<string, boolean>>({
    sdr: true,
    ocr: true,
    scn: true,
    'oscal-ar': true,
  });
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<RunResult | null>(null);

  function toggle(id: string) {
    setSelected((s) => ({ ...s, [id]: !s[id] }));
  }

  async function run() {
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const artifacts = ARTIFACTS.map((a) => a.id).filter((id) => selected[id]);
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ artifacts }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Run failed.');
      setResult(data as RunResult);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Run failed.');
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <h1>ksi-harness</h1>
      <p className="thesis">
        Continuous control monitoring for <b>FedRAMP 20x</b>. It pins FedRAMP&apos;s own machine-readable rules
        as source of truth, collects evidence with <b>population reconciliation</b>, and reports coverage that
        refuses to overstate — then emits schema-valid 20x artifacts from that same state.
      </p>
      <p className="sub">
        <a href="https://github.com/RootCawsLLC/ksi-harness">Source</a> · This runs the <b>real tool</b> against
        bundled synthetic fixtures — no credentials, no cloud account, nothing contacts a real system.
      </p>

      <div className="callout">
        The headline number is <b>zero fully-automated indicators</b>, and that is the point. There are 29
        implemented checks and 25 indicators with real, chain-verified passing evidence behind them — but an
        indicator only reaches <b>automated</b> when someone writes the argument that its checks leave nothing
        material out. A conventional tool would render this as &ldquo;north of 50% coverage.&rdquo;
      </div>

      <div className="panel">
        <div style={{ fontSize: '0.85rem', color: 'var(--ink-2)', marginBottom: '0.6rem' }}>
          Emit these FedRAMP 20x / OSCAL artifacts from the collected state:
        </div>
        <div className="layers">
          {ARTIFACTS.map((a) => (
            <label key={a.id} className="layer">
              <input type="checkbox" checked={!!selected[a.id]} onChange={() => toggle(a.id)} />
              <span>
                <span className="lt">{a.name}</span>
                <br />
                <span className="ld">{a.blurb}</span>
              </span>
            </label>
          ))}
        </div>

        <div className="run-row">
          <button className="run" onClick={run} disabled={running}>
            {running ? 'Running…' : 'Run the harness'}
          </button>
          {running && (
            <span className="notes">
              <span className="spinner" /> Collecting evidence twice (to establish a cadence and a diff), building
              control state, then emitting artifacts. A few seconds.
            </span>
          )}
        </div>
      </div>

      {error && <div className="err">{error}</div>}

      {result && <Results result={result} />}
    </>
  );
}

function pct(n: number, total: number) {
  return total > 0 ? (n / total) * 100 : 0;
}

function Results({ result }: { result: RunResult }) {
  const c = result.counts;
  const cov = c.coverage;
  const applicable = c.applicable;
  const withEvidence = c.evidence_state['failing'] + c.evidence_state['satisfied-in-part'] + c.evidence_state['degraded'];
  const chainOk = result.evidence.chain_breaks.length === 0 && result.evidence.tampered.length === 0 && result.evidence.unreadable.length === 0;

  const covOrder: { key: string; label: string }[] = [
    { key: 'automated', label: 'automated' },
    { key: 'partial', label: 'partial' },
    { key: 'manual', label: 'manual' },
    { key: 'unaddressed', label: 'unaddressed' },
  ];

  return (
    <>
      <h2>The headline number</h2>
      <div className="panel">
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.75rem' }}>
          <span className="headline">{cov.automated}</span>
          <span className="headline-note">
            indicators reported <b>fully automated</b>, of <b>{applicable}</b> applicable. Not a rendering
            artifact — a finding about the harness.
          </span>
        </div>
        <div className="ruleline">
          FedRAMP Consolidated Rules {result.ruleset.version} · updated {result.ruleset.last_updated} ·
          sha256:{result.ruleset.sha256.slice(0, 16)} · Class {result.klass.toUpperCase()}
        </div>

        <div className="covbar" title="automated / partial / manual / unaddressed">
          {covOrder.map((s) =>
            cov[s.key] ? (
              <div key={s.key} className={`covseg ${s.key}`} style={{ width: `${pct(cov[s.key], applicable)}%` }}>
                {cov[s.key]}
              </div>
            ) : null,
          )}
        </div>
        <div className="covlegend">
          {covOrder.map((s) => (
            <span key={s.key}>
              <span className={`dot ${s.key}`} />
              {s.label} {cov[s.key]}
            </span>
          ))}
        </div>

        <div className="chip-row">
          <span className="chip">{result.counts.total} indicators in ruleset</span>
          <span className="chip">{withEvidence} with automated evidence</span>
          <span className="chip">{result.evidence.bundle_count} evidence bundles</span>
          <span className={`chip ${result.routesValid ? 'ok' : 'bad'}`}>
            routing map {result.routesValid ? 'valid' : 'INVALID'}
          </span>
          <span className={`chip ${chainOk ? 'ok' : 'bad'}`}>
            {chainOk ? 'every hash chain intact' : 'chain / hash problem'}
          </span>
          <span className="chip">{result.collectFailures.length} collector failures</span>
          <span className="chip">{(result.durationMs / 1000).toFixed(1)}s</span>
        </div>

        {result.evidence.fixture_bundles > 0 && (
          <div className="fixture-warn">
            {result.evidence.fixture_bundles} of {result.evidence.bundle_count} evidence bundles came from fixtures.
            This describes the harness, not a production environment — and the tool stamps every bundle as such so
            it can never be mistaken for real evidence.
          </div>
        )}
      </div>

      <h2>Evidence outcome — pass/fail populations, not samples</h2>
      <div className="panel">
        <div className="summary">
          {Object.entries(c.evidence_state)
            .filter(([, n]) => n)
            .map(([k, n]) => (
              <span key={k}>
                {k}: <b>{n}</b>
              </span>
            ))}
        </div>
        <p className="notes" style={{ marginTop: '0.6rem' }}>
          Coverage and evidence outcome are separate claims. &ldquo;partial&rdquo; means real automated evidence
          that does not settle the whole capability; &ldquo;failing&rdquo; means at least one declared check found
          a failure across the full enumerated population.
        </p>
        {result.diff && (
          <div className="summary" style={{ marginTop: '0.4rem' }}>
            <span>
              since the first collection — regressions: <b>{result.diff.counts.regressed_items ?? 0}</b>
            </span>
            <span>fixed: <b>{result.diff.counts.fixed_items ?? 0}</b></span>
            <span>completeness lost: <b>{result.diff.counts.completeness_lost ?? 0}</b></span>
          </div>
        )}
      </div>

      <h2>By theme</h2>
      <div className="panel tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Theme</th>
              <th className="num">Indicators</th>
              <th className="num">Automated / partial</th>
              <th className="num">Manual</th>
              <th className="num">Unaddressed</th>
            </tr>
          </thead>
          <tbody>
            {result.themes.map((t) => {
              const inTheme = result.indicators.filter((i) => i.theme === t.short && i.applicable);
              if (inTheme.length === 0) return null;
              return (
                <tr key={t.short}>
                  <td>
                    <b>{t.short}</b> — {t.name}
                  </td>
                  <td className="num">{inTheme.length}</td>
                  <td className="num">{inTheme.filter((i) => ['automated', 'partial'].includes(i.coverage)).length}</td>
                  <td className="num">{inTheme.filter((i) => i.coverage === 'manual').length}</td>
                  <td className="num">{inTheme.filter((i) => i.coverage === 'unaddressed').length}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {result.findings.length > 0 && (
        <>
          <h2>Open findings — {result.findings.length}</h2>
          <div className="panel">
            <p className="notes" style={{ marginTop: 0 }}>
              Indicators with an automated claim whose evidence is failing, degraded or absent. (Expected here:
              the fixtures include deliberately non-conforming resources.)
            </p>
            {result.findings.map((f) => (
              <div key={f.indicator} className="finding">
                <span className="fi-id">{f.indicator}</span> — {f.name} · <b>{f.evidence_state}</b>
                <div className="notes">
                  {f.checks
                    .map((ch) => `${ch.check_id} ${ch.result}${ch.failing_items ? ` (${ch.failing_items} failing)` : ''}`)
                    .join(', ')}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      <h2>Every applicable indicator</h2>
      <div>
        {result.indicators
          .filter((i) => i.applicable)
          .map((i) => (
            <details key={i.id} className="indicator">
              <summary>
                <span className="ind-id">{i.id}</span>
                <span className="ind-name">
                  {i.name}
                  {i.optional ? ' (optional at this class)' : ''}
                </span>
                <span className={`badge cov-${i.coverage}`}>{i.coverage}</span>
                <span className={`badge ev-${i.evidence_state}`}>{i.evidence_state}</span>
              </summary>
              <div className="ind-body">
                <div className="meta">
                  theme {i.theme} · {i.controls.length} NIST 800-53 control(s)
                  {i.cadence?.claimed
                    ? ` · cadence ${i.cadence.claimed}${i.cadence.met === true ? ' ✓' : i.cadence.met === false ? ' ✗' : ''}`
                    : ''}
                </div>

                {i.checks.length > 0
                  ? i.checks.map((ch) => (
                      <div key={ch.check_id} className="check">
                        <div className="check-head">
                          <span className="check-id">{ch.check_id}</span>
                          <span className={`res ${ch.present ? ch.result ?? 'error' : 'absent'}`}>
                            {ch.present ? ch.result ?? 'error' : 'absent'}
                          </span>
                          {ch.run_count > 0 && <span className="notes">{ch.run_count} run(s)</span>}
                          {ch.fixture && <span className="notes">fixture</span>}
                        </div>
                        {ch.population && (
                          <div className="pop">
                            population reconciliation:{' '}
                            <span className="recon">
                              {ch.population.examined ?? '—'} of {ch.population.expected ?? '—'} examined
                            </span>
                            {ch.population.complete ? ' · complete' : ' · INCOMPLETE'}
                            {typeof ch.population.decidable === 'number'
                              ? ` · ${ch.population.decidable} decidable`
                              : ''}
                            {ch.metric && (
                              <>
                                {' '}
                                · metric {ch.metric.metric_id} = <b>{ch.metric.value}</b> {ch.metric.unit}
                              </>
                            )}
                            {ch.population.source_of_truth && (
                              <span className="sot">source of truth: {ch.population.source_of_truth}</span>
                            )}
                          </div>
                        )}
                      </div>
                    ))
                  : (
                    <div className="notes">No automated checks declared for this indicator.</div>
                  )}

                {i.unautomated.length > 0 && (
                  <>
                    <div className="meta" style={{ marginBottom: 0 }}>What the automation does not establish:</div>
                    <ul className="gaps">
                      {i.unautomated.map((g, k) => (
                        <li key={k}>{g.trim().replace(/\s+/g, ' ')}</li>
                      ))}
                    </ul>
                  </>
                )}
                {i.coverage === 'unaddressed' && i.reason && (
                  <div className="pop" style={{ marginTop: '0.5rem' }}>
                    <b>Unaddressed.</b> {i.reason.trim().replace(/\s+/g, ' ')}
                    {i.next && (
                      <span className="sot">
                        Next: {i.next.trim().replace(/\s+/g, ' ')}
                      </span>
                    )}
                  </div>
                )}
              </div>
            </details>
          ))}
      </div>

      <h2>Emitted artifacts</h2>
      {result.artifacts.length === 0 ? (
        <div className="panel empty">No artifacts were selected.</div>
      ) : (
        <div>
          {result.artifacts.map((a) => (
            <details key={a.kind} className="artifact">
              <summary>
                <span className="a-kind">{a.kind}</span>
                <span className="a-label">{a.label}</span>
                {a.error ? (
                  <span className="badge val-no">error</span>
                ) : (
                  <span className={`badge ${a.validated ? 'val-yes' : 'val-no'}`}>
                    {a.validated ? 'schema-validated' : 'not validated here'}
                  </span>
                )}
                {typeof a.bytes === 'number' && <span className="notes">{(a.bytes / 1024).toFixed(1)} KB</span>}
              </summary>
              {a.error ? (
                <pre>{a.error}</pre>
              ) : (
                <pre>{JSON.stringify(a.document, null, 2)}</pre>
              )}
            </details>
          ))}
        </div>
      )}
    </>
  );
}
