import { hostname } from 'node:os';
import { createLogger, requireSecret } from '@xpm/core';
import { AgentRuntime } from './runtime.js';

const role = process.env.AGENT_ROLE;
if (role !== 'pm' && role !== 'dev') throw new Error('AGENT_ROLE must be pm or dev');
const log = createLogger(`${role}-runtime`);
const runtime = new AgentRuntime({
  gatewayUrl: process.env.XPM_GATEWAY_URL ?? 'http://gateway:4100',
  token: requireSecret('XPM_RUNTIME_TOKEN'),
  runtimeId: `${role}-${hostname()}`,
  log,
});
runtime.start();
log.info({ role }, 'agent runtime started');
for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, async () => {
    await runtime.stop();
    process.exit(0);
  });
}
