export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

let csrfToken: string | null = null;
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

/** Called when any request comes back 401 so the app can show the login screen. */
let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = init.method ?? 'GET';
  const headers: Record<string, string> = { accept: 'application/json' };
  if (init.body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET' && csrfToken) headers['x-csrf-token'] = csrfToken;
  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  const data = res.headers.get('content-type')?.includes('application/json') ? await res.json() : null;
  if (!res.ok) {
    if (res.status === 401 && path !== '/api/auth/login') onUnauthorized();
    throw new ApiError(res.status, data?.message ?? data?.error ?? `Request failed (${res.status})`);
  }
  return data as T;
}

export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';

export interface Job {
  id: string;
  idempotencyKey: string;
  type: string;
  status: JobStatus;
  attempts: number;
  maxAttempts: number;
  runAt: string;
  leaseOwner: string | null;
  leaseExpiresAt: string | null;
  fence: number;
  lastError: string | null;
  result: unknown;
  payload: unknown;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
}

export interface JobAttempt {
  id: number;
  attemptNo: number;
  fence: number;
  workerId: string;
  status: string;
  error: string | null;
  startedAt: string;
  finishedAt: string | null;
}

export interface Health {
  database: { ok: boolean; latencyMs: number };
  migration: { name: string; appliedAt: string } | null;
  workers: { workerId: string; startedAt: string; lastSeenAt: string; healthy: boolean; activeJobs: number }[];
  queue: Record<JobStatus, number>;
  sampleMode: boolean;
  serverTime: string;
}

export interface Case {
  id: string;
  reference: string;
  title: string;
  kind: string;
  status: string;
  summary: string;
  isSample: boolean;
  createdAt: string;
}

export interface Session {
  username: string;
  csrfToken: string;
  expiresAt: string;
  sampleMode?: boolean;
}
