import { useCallback, useEffect, useState, type FormEvent } from 'react';
import {
  api,
  ApiError,
  setCsrfToken,
  setUnauthorizedHandler,
  type Case,
  type Health,
  type Job,
  type JobAttempt,
  type JobStatus,
  type Session,
} from './api';

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '—');

function usePoll<T>(load: () => Promise<T>, intervalMs: number, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = useCallback(async () => {
    try {
      setData(await load());
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), intervalMs);
    return () => clearInterval(t);
  }, [refresh, intervalMs]);
  return { data, error, refresh };
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

function Login({ onLogin }: { onLogin: (s: Session) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const s = await api<Session>('/api/auth/login', { method: 'POST', body: { username, password } });
      setPassword('');
      onLogin(s);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not reach the server');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form className="card login-card" onSubmit={submit}>
        <h1>Questalina Desk</h1>
        <p className="muted">Owner sign-in</p>
        <label>
          Username
          <input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
        </label>
        <label>
          Password
          <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {error && <p className="error" role="alert">{error}</p>}
        <button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

function HealthPanel() {
  const { data, error } = usePoll(() => api<Health>('/api/system/health'), 5000, []);
  if (error) return <section className="card"><h2>System</h2><p className="error">{error}</p></section>;
  if (!data) return <section className="card"><h2>System</h2><p className="muted">Loading…</p></section>;
  const healthyWorkers = data.workers.filter((w) => w.healthy);
  return (
    <section className="card">
      <h2>System</h2>
      <div className="stats">
        <div className="stat">
          <span className={`dot ${data.database.ok ? 'ok' : 'bad'}`} />
          <div><strong>Database</strong><span className="muted">{data.database.latencyMs} ms · {data.migration?.name ?? 'no migrations'}</span></div>
        </div>
        <div className="stat">
          <span className={`dot ${healthyWorkers.length > 0 ? 'ok' : 'bad'}`} />
          <div>
            <strong>Workers</strong>
            <span className="muted">
              {healthyWorkers.length} healthy{data.workers.length > healthyWorkers.length ? ` · ${data.workers.length - healthyWorkers.length} stale` : ''}
            </span>
          </div>
        </div>
        {(['queued', 'running', 'failed'] as const).map((s) => (
          <div className="stat" key={s}>
            <span className={`dot ${s === 'failed' && data.queue.failed > 0 ? 'bad' : 'neutral'}`} />
            <div><strong>{data.queue[s]}</strong><span className="muted">{s}</span></div>
          </div>
        ))}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

interface JobPage {
  jobs: Job[];
  next: { beforeCreatedAt: string; beforeId: string } | null;
}

function JobDetail({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { data, error, refresh } = usePoll(() => api<{ job: Job; attempts: JobAttempt[] }>(`/api/jobs/${id}`), 3000, [id]);
  const [actionError, setActionError] = useState<string | null>(null);

  async function act(action: 'cancel' | 'retry') {
    setActionError(null);
    try {
      await api(`/api/jobs/${id}/${action}`, { method: 'POST' });
      await refresh();
      onChanged();
    } catch (e) {
      setActionError((e as Error).message);
    }
  }

  return (
    <aside className="card detail" aria-label="Job detail">
      <div className="row">
        <h2>Job</h2>
        <button className="ghost" onClick={onClose}>Close</button>
      </div>
      {error && <p className="error">{error}</p>}
      {data && (
        <>
          <dl>
            <dt>Key</dt><dd><code>{data.job.idempotencyKey}</code></dd>
            <dt>Type</dt><dd>{data.job.type}</dd>
            <dt>Status</dt><dd><span className={`badge ${data.job.status}`}>{data.job.status}</span></dd>
            <dt>Attempts</dt><dd>{data.job.attempts} / {data.job.maxAttempts} · fence {data.job.fence}</dd>
            <dt>Run at</dt><dd>{fmt(data.job.runAt)}</dd>
            {data.job.leaseOwner && (<><dt>Lease</dt><dd>{data.job.leaseOwner} until {fmt(data.job.leaseExpiresAt)}</dd></>)}
            {data.job.lastError && (<><dt>Last error</dt><dd className="error">{data.job.lastError}</dd></>)}
            {data.job.result !== null && (<><dt>Result</dt><dd><pre>{JSON.stringify(data.job.result, null, 2)}</pre></dd></>)}
          </dl>
          <div className="row gap">
            {(data.job.status === 'queued' || data.job.status === 'running') && <button className="danger" onClick={() => act('cancel')}>Cancel</button>}
            {(data.job.status === 'failed' || data.job.status === 'cancelled') && <button onClick={() => act('retry')}>Retry</button>}
          </div>
          {actionError && <p className="error">{actionError}</p>}
          <h3>Attempts</h3>
          <div className="scroll-x">
            <table>
              <thead><tr><th>#</th><th>Fence</th><th>Worker</th><th>Status</th><th>Started</th><th>Finished</th><th>Error</th></tr></thead>
              <tbody>
                {data.attempts.map((a) => (
                  <tr key={a.id}>
                    <td>{a.attemptNo}</td><td>{a.fence}</td><td><code>{a.workerId}</code></td>
                    <td><span className={`badge ${a.status}`}>{a.status}</span></td>
                    <td>{fmt(a.startedAt)}</td><td>{fmt(a.finishedAt)}</td><td className="wrap">{a.error ?? ''}</td>
                  </tr>
                ))}
                {data.attempts.length === 0 && <tr><td colSpan={7} className="muted">No attempts yet</td></tr>}
              </tbody>
            </table>
          </div>
        </>
      )}
    </aside>
  );
}

function JobsPanel({ sampleMode }: { sampleMode: boolean }) {
  const [status, setStatus] = useState<JobStatus | ''>('');
  const [cursors, setCursors] = useState<JobPage['next'][]>([null]);
  const cursor = cursors.at(-1) ?? null;
  const [selected, setSelected] = useState<string | null>(null);
  const query = new URLSearchParams({ limit: '25' });
  if (status) query.set('status', status);
  if (cursor) {
    query.set('beforeCreatedAt', cursor.beforeCreatedAt);
    query.set('beforeId', cursor.beforeId);
  }
  const qs = query.toString();
  const { data, error, refresh } = usePoll(() => api<JobPage>(`/api/jobs?${qs}`), 3000, [qs]);
  const [demoMsg, setDemoMsg] = useState<string | null>(null);

  async function demo(kind: 'echo' | 'sleep' | 'fail' | 'fail_permanent') {
    try {
      const r = await api<{ job: Job; created: boolean }>('/api/demo/jobs', {
        method: 'POST',
        body: kind === 'sleep' ? { kind, seconds: 20 } : { kind },
      });
      setDemoMsg(`Enqueued ${r.job.type}`);
      await refresh();
    } catch (e) {
      setDemoMsg((e as Error).message);
    }
  }

  return (
    <div className="jobs-layout">
      <section className="card">
        <div className="row">
          <h2>Jobs</h2>
          <select aria-label="Filter by status" value={status} onChange={(e) => { setStatus(e.target.value as JobStatus | ''); setCursors([null]); }}>
            <option value="">All statuses</option>
            {['queued', 'running', 'succeeded', 'failed', 'cancelled'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        {sampleMode && (
          <div className="row gap demo">
            <span className="muted">Sample jobs:</span>
            <button className="ghost" onClick={() => demo('echo')}>Echo</button>
            <button className="ghost" onClick={() => demo('sleep')}>Sleep 20s</button>
            <button className="ghost" onClick={() => demo('fail')}>Flaky (retries)</button>
            <button className="ghost" onClick={() => demo('fail_permanent')}>Permanent failure</button>
            {demoMsg && <span className="muted">{demoMsg}</span>}
          </div>
        )}
        {error && <p className="error">{error}</p>}
        <div className="scroll-x">
          <table>
            <thead><tr><th>Created</th><th>Type</th><th>Key</th><th>Status</th><th>Attempts</th></tr></thead>
            <tbody>
              {data?.jobs.map((j) => (
                <tr key={j.id} className={`clickable ${selected === j.id ? 'selected' : ''}`} onClick={() => setSelected(j.id)}>
                  <td>{fmt(j.createdAt)}</td><td>{j.type}</td><td><code>{j.idempotencyKey}</code></td>
                  <td><span className={`badge ${j.status}`}>{j.status}</span></td><td>{j.attempts}/{j.maxAttempts}</td>
                </tr>
              ))}
              {data && data.jobs.length === 0 && <tr><td colSpan={5} className="muted">No jobs</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="row gap">
          <button className="ghost" disabled={cursors.length <= 1} onClick={() => setCursors((c) => c.slice(0, -1))}>Newer</button>
          <button className="ghost" disabled={!data?.next} onClick={() => data?.next && setCursors((c) => [...c, data.next])}>Older</button>
        </div>
      </section>
      {selected && <JobDetail id={selected} onClose={() => setSelected(null)} onChanged={() => void refresh()} />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

function CasesPanel() {
  const { data, error } = usePoll(() => api<{ cases: Case[] }>('/api/cases'), 15000, []);
  return (
    <section className="card">
      <h2>Cases</h2>
      {error && <p className="error">{error}</p>}
      <ul className="cases">
        {data?.cases.map((c) => (
          <li key={c.id}>
            <div className="row">
              <strong>{c.title}</strong>
              <span className={`badge ${c.status}`}>{c.status.replace('_', ' ')}</span>
            </div>
            <span className="muted">{c.reference} · {c.kind.replace('_', ' ')}{c.isSample ? ' · sample' : ''}</span>
            <p>{c.summary}</p>
          </li>
        ))}
        {data && data.cases.length === 0 && <li className="muted">No cases yet. Intake arrives in Milestone 3.</li>}
      </ul>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

type Tab = 'overview' | 'jobs';

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [checked, setChecked] = useState(false);
  const [tab, setTab] = useState<Tab>('overview');

  const applySession = useCallback((s: Session | null) => {
    setCsrfToken(s?.csrfToken ?? null);
    setSession(s);
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => applySession(null));
    api<Session>('/api/auth/session')
      .then(applySession)
      .catch(() => applySession(null))
      .finally(() => setChecked(true));
  }, [applySession]);

  async function logout() {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } finally {
      applySession(null);
    }
  }

  if (!checked) return null;
  if (!session) {
    return (
      <Login
        onLogin={(s) => {
          // The login response lacks sampleMode; fetch the full session.
          applySession(s);
          api<Session>('/api/auth/session').then(applySession).catch(() => {});
        }}
      />
    );
  }

  return (
    <>
      {session.sampleMode && <div className="sample-banner">Sample data mode: everything shown here is fictional test data.</div>}
      <header className="topbar">
        <strong>Questalina Desk</strong>
        <nav>
          <button className={tab === 'overview' ? 'tab active' : 'tab'} onClick={() => setTab('overview')}>Overview</button>
          <button className={tab === 'jobs' ? 'tab active' : 'tab'} onClick={() => setTab('jobs')}>Jobs</button>
        </nav>
        <div className="row gap">
          <span className="muted">{session.username}</span>
          <button className="ghost" onClick={logout}>Sign out</button>
        </div>
      </header>
      <main className="content">
        {tab === 'overview' && (
          <>
            <HealthPanel />
            <CasesPanel />
          </>
        )}
        {tab === 'jobs' && <JobsPanel sampleMode={session.sampleMode ?? false} />}
      </main>
    </>
  );
}
