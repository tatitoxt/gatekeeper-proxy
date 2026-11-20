import { ChildProcess, spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const ROOT = path.resolve(__dirname, '..');
export const ADMIN_TOKEN = 'e2e-admin-token-not-a-secret';

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

export interface Running {
  proc: ChildProcess;
  output: () => string;
  stop: (signal?: NodeJS.Signals) => Promise<number | null>;
}

function launch(args: string[], env: NodeJS.ProcessEnv, readyText: string, timeoutMs = 15_000): Promise<Running> {
  const proc = spawn(process.execPath, args, { cwd: ROOT, env: { ...process.env, ...env }, stdio: 'pipe' });
  let out = '';
  const exited = new Promise<number | null>((resolve) => proc.on('exit', (code) => resolve(code)));
  const running: Running = {
    proc,
    output: () => out,
    stop: async (signal = 'SIGTERM') => {
      if (proc.exitCode === null && proc.signalCode === null) proc.kill(signal);
      return exited;
    }
  };
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      proc.kill('SIGKILL');
      reject(new Error(`Timed out waiting for "${readyText}". Output:\n${out}`));
    }, timeoutMs);
    const onData = (chunk: Buffer) => {
      out += chunk.toString('utf-8');
      if (out.includes(readyText)) {
        clearTimeout(timer);
        resolve(running);
      }
    };
    proc.stdout.on('data', onData);
    proc.stderr.on('data', onData);
    proc.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Process exited with ${code} before "${readyText}". Output:\n${out}`));
    });
  });
}

/** The JSON shape of gatekeeper.config.json as edited by the tests (loosely typed on purpose). */
export interface JsonConfig {
  server: Record<string, unknown>;
  routes: Array<{ pathPrefix: string; targets: string[]; [key: string]: unknown }>;
  [key: string]: unknown;
}

export interface Stack {
  proxyUrl: string;
  adminUrl: string;
  configPath: string;
  upstreamPorts: number[];
  gateway: Running;
  upstreams: Running;
  stop: () => Promise<void>;
}

/**
 * Starts the synthetic demo upstreams and the compiled gateway (`node dist/index.js`)
 * exactly as a user would, with a temporary config file and random free ports.
 */
export async function startStack(mutate: (config: JsonConfig) => void = () => {}): Promise<Stack> {
  const entry = path.join(ROOT, 'dist', 'index.js');
  if (!fs.existsSync(entry)) throw new Error('dist/index.js not found: run `npm run build` first');

  const [proxyPort, adminPort, ...upstreamPorts] = await Promise.all([1, 2, 3, 4, 5].map(() => freePort()));
  const upstreams = await launch(
    ['scripts/demo-upstreams.mjs'],
    { DEMO_UPSTREAM_PORTS: upstreamPorts.join(',') },
    'demo upstreams ready'
  );

  const example: JsonConfig = JSON.parse(fs.readFileSync(path.join(ROOT, 'gatekeeper.config.json'), 'utf-8'));
  example.server = { ...example.server, port: proxyPort, adminPort, host: '127.0.0.1', adminHost: '127.0.0.1' };
  const byPort: Record<string, string> = { '9001': `${upstreamPorts[0]}`, '9002': `${upstreamPorts[1]}`, '9003': `${upstreamPorts[2]}` };
  for (const route of example.routes) {
    route.targets = route.targets.map((t) => t.replace(/:(900[123])$/, (_m: string, p: string) => `:${byPort[p]}`));
  }
  example.healthCheck = { intervalMs: 500, timeoutMs: 500 };
  mutate(example);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatekeeper-e2e-'));
  const configPath = path.join(dir, 'gatekeeper.config.json');
  fs.writeFileSync(configPath, JSON.stringify(example, null, 2));

  let gateway: Running;
  try {
    gateway = await launch(
      [entry],
      {
        GATEKEEPER_CONFIG: configPath,
        GATEKEEPER_ADMIN_TOKEN: ADMIN_TOKEN,
        LOG_FORMAT: 'json',
        LOG_LEVEL: 'info',
        NODE_ENV: 'production'
      },
      'Gatekeeper ready'
    );
  } catch (err) {
    await upstreams.stop();
    throw err;
  }

  return {
    proxyUrl: `http://127.0.0.1:${proxyPort}`,
    adminUrl: `http://127.0.0.1:${adminPort}`,
    configPath,
    upstreamPorts,
    gateway,
    upstreams,
    stop: async () => {
      await gateway.stop();
      await upstreams.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };
}

export async function waitFor(check: () => Promise<boolean>, timeoutMs = 5_000, stepMs = 100): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  throw new Error(`Condition not met within ${timeoutMs}ms`);
}
