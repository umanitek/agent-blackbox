#!/usr/bin/env node

import { access } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const BLACKBOX_BLAZEGRAPH_JAVA_OPTS = '-Xms512m -Xmx4g';
const BLACKBOX_BLAZEGRAPH_CPUS = '4';
const MINIMUM_BLAZEGRAPH_HEAP_BYTES = 4 * 1024 * 1024 * 1024;

function fail(message) {
  process.stderr.write(`Blazegraph setup failed: ${message}\n`);
  process.exit(1);
}

const args = process.argv.slice(2);
const healthCheck = args[0] === 'check';
const namespaceReset = args[0] === 'reset';
const [dkgCheckout, namespace, portText] = (healthCheck || namespaceReset)
  ? args.slice(1)
  : args;
if (!dkgCheckout || !namespace) {
  fail('usage: blackbox-blazegraph.mjs <dkg-checkout> <namespace> [preferred-port]');
}

if (namespaceReset) {
  const expectedNamespace = String(portText || '');
  let endpoint;
  try {
    endpoint = new URL(namespace);
  } catch {
    fail(`invalid Blazegraph endpoint: ${namespace}`);
  }
  const host = endpoint.hostname.toLowerCase();
  const parts = endpoint.pathname.split('/').filter(Boolean).map(decodeURIComponent);
  const namespaceIndex = parts.lastIndexOf('namespace');
  const endpointNamespace = namespaceIndex >= 0 ? parts[namespaceIndex + 1] : '';
  if (!['127.0.0.1', 'localhost', '::1'].includes(host)) {
    fail('refusing to reset a non-local Blazegraph endpoint');
  }
  if (!expectedNamespace || endpointNamespace !== expectedNamespace || parts.at(-1) !== 'sparql') {
    fail(`refusing to reset endpoint outside namespace "${expectedNamespace}"`);
  }
  const request = async (body, contentType) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 60_000);
    try {
      return await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': contentType, accept: 'application/sparql-results+json' },
        body,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  };
  try {
    const cleared = await request('DROP ALL', 'application/sparql-update');
    if (!cleared.ok) {
      throw new Error(`DROP ALL returned HTTP ${cleared.status}: ${await cleared.text()}`);
    }
    const checked = await request(
      'SELECT (COUNT(*) AS ?count) WHERE { { ?s ?p ?o } UNION { GRAPH ?g { ?s ?p ?o } } }',
      'application/sparql-query',
    );
    if (!checked.ok) {
      throw new Error(`empty-store verification returned HTTP ${checked.status}`);
    }
    const payload = await checked.json();
    const count = Number(payload?.results?.bindings?.[0]?.count?.value ?? NaN);
    if (count !== 0) {
      throw new Error(`namespace still contains ${Number.isFinite(count) ? count : 'unknown'} triples`);
    }
    process.stdout.write(`${JSON.stringify({ ok: true, namespace: expectedNamespace, triples: 0 })}\n`);
    process.exit(0);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}

if (healthCheck) {
  const dkgRoot = path.resolve(dkgCheckout);
  const modulePaths = [
    path.join(
      dkgRoot,
      'node_modules',
      '@origintrail-official',
      'dkg',
      'dist',
      'daemon',
      'store-health-check.js',
    ),
    path.join(dkgRoot, 'packages', 'cli', 'dist', 'daemon', 'store-health-check.js'),
  ];
  try {
    let modulePath;
    for (const candidate of modulePaths) {
      try {
        await access(candidate);
        modulePath = candidate;
        break;
      } catch {}
    }
    if (!modulePath) {
      throw new Error(`published DKG store health check not found under ${dkgRoot}`);
    }
    const { checkExternalStoreReachable, formatHealthCheckFailure } = await import(
      pathToFileURL(modulePath).href
    );
    const result = await checkExternalStoreReachable({
      storeConfig: { backend: 'blazegraph', options: { url: namespace } },
      timeoutMs: 10_000,
    });
    if (!result.ok) {
      throw new Error(formatHealthCheckFailure(result));
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exit(0);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}

const port = Number(portText || '9999');
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  fail(`invalid preferred port: ${portText}`);
}

const dkgRoot = path.resolve(dkgCheckout);
const modulePaths = [
  path.join(
    dkgRoot,
    'node_modules',
    '@origintrail-official',
    'dkg',
    'dist',
    'daemon',
    'blazegraph-docker.js',
  ),
  // Kept as a migration fallback so an interrupted custom-checkout install can
  // still explain itself cleanly before the npm package replaces it.
  path.join(dkgRoot, 'packages', 'cli', 'dist', 'daemon', 'blazegraph-docker.js'),
];

function runDocker(args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString('utf-8'); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf-8'); });
    const timer = opts.timeoutMs
      ? setTimeout(() => child.kill('SIGKILL'), opts.timeoutMs)
      : undefined;
    child.once('error', (error) => {
      if (timer) clearTimeout(timer);
      reject(error);
    });
    child.once('close', (exitCode) => {
      if (timer) clearTimeout(timer);
      resolve({ stdout, stderr, exitCode: exitCode ?? 0 });
    });
  });
}

function heapBytes(javaOpts) {
  const match = String(javaOpts || '').match(/(?:^|\s)-Xmx(\d+)([kKmMgG]?)(?:\s|$)/);
  if (!match) return 0;
  const units = { '': 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3 };
  return Number(match[1]) * units[match[2].toLowerCase()];
}

function javaOptsFromInspect(stdout) {
  try {
    const containers = JSON.parse(stdout);
    const env = containers?.[0]?.Config?.Env;
    if (!Array.isArray(env)) return '';
    const entry = env.find((value) => String(value).startsWith('JAVA_OPTS='));
    return entry ? String(entry).slice('JAVA_OPTS='.length) : '';
  } catch {
    return '';
  }
}

function backupContainerName(name) {
  return `${name}-pre-4g-${Date.now()}`;
}

function blackboxDockerRunner(log) {
  return {
    async run(args, opts) {
      if (args[0] === 'run' && !args.some((arg) => String(arg).startsWith('JAVA_OPTS='))) {
        return runDocker(
          [
            'run',
            '--cpus',
            BLACKBOX_BLAZEGRAPH_CPUS,
            '-e',
            `JAVA_OPTS=${BLACKBOX_BLAZEGRAPH_JAVA_OPTS}`,
            ...args.slice(1),
          ],
          opts,
        );
      }

      const result = await runDocker([...args], opts);
      if (args[0] !== 'inspect' || result.exitCode !== 0) return result;

      const javaOpts = javaOptsFromInspect(result.stdout);
      if (heapBytes(javaOpts) >= MINIMUM_BLAZEGRAPH_HEAP_BYTES) {
        const name = String(args[1] || 'dkg-blazegraph');
        const limited = await runDocker(
          ['update', '--cpus', BLACKBOX_BLAZEGRAPH_CPUS, name],
          { timeoutMs: 10_000 },
        );
        if (limited.exitCode !== 0) {
          throw new Error(`Could not apply the Blackbox CPU limit to "${name}": ${limited.stderr.trim()}`);
        }
        return result;
      }

      const name = String(args[1] || 'dkg-blazegraph');
      const backup = backupContainerName(name);
      log(`  Existing container "${name}" uses ${javaOpts || 'the image-default heap'}; replacing it with a 4 GB instance.`);
      const stopped = await runDocker(['stop', name], { timeoutMs: 30_000 });
      if (stopped.exitCode !== 0) {
        throw new Error(`Could not stop undersized Blazegraph container "${name}": ${stopped.stderr.trim()}`);
      }
      const renamed = await runDocker(['rename', name, backup], { timeoutMs: 10_000 });
      if (renamed.exitCode !== 0) {
        throw new Error(`Could not preserve undersized Blazegraph container "${name}": ${renamed.stderr.trim()}`);
      }
      log(`  Preserved the old local store as stopped container "${backup}".`);
      return { stdout: '', stderr: 'container migrated to a recoverable backup', exitCode: 1 };
    },
  };
}

try {
  let modulePath;
  for (const candidate of modulePaths) {
    try {
      await access(candidate);
      modulePath = candidate;
      break;
    } catch {
      // Try the next supported install layout.
    }
  }
  if (!modulePath) {
    throw new Error(`published DKG Blazegraph provisioner not found under ${dkgRoot}`);
  }
  const { provisionBlazegraphDocker } = await import(pathToFileURL(modulePath).href);
  const result = await provisionBlazegraphDocker({
    namespace,
    port,
    // The first Jetty/WAR boot can take over two minutes on Docker Desktop.
    // Keep the installer alive while the container is making forward progress.
    pollTimeoutMs: 300_000,
    log: (message) => process.stderr.write(`${message}\n`),
    docker: blackboxDockerRunner((message) => process.stderr.write(`${message}\n`)),
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
