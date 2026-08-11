#!/usr/bin/env node

import { access } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const BLACKBOX_BLAZEGRAPH_JAVA_OPTS = '-Xms512m -Xmx4g';
const BLACKBOX_BLAZEGRAPH_CPUS = '4';
const MINIMUM_BLAZEGRAPH_HEAP_BYTES = 4 * 1024 * 1024 * 1024;
const EFFECTIVE_HEAP_MARKER = 'blackbox-effective-blazegraph-heap';
const LEGACY_HEAP_PATCH = [
  'set -eu',
  'setenv=/opt/tomcat/bin/setenv.sh',
  'test -f "$setenv"',
  'cp "$setenv" "$setenv.blackbox-pre-4g"',
  `printf '\\n# ${EFFECTIVE_HEAP_MARKER}\\nexport JAVA_OPTS="${BLACKBOX_BLAZEGRAPH_JAVA_OPTS}"\\n' >> "$setenv"`,
];

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

function containerFromInspect(stdout) {
  try {
    const containers = JSON.parse(stdout);
    return containers?.[0] && typeof containers[0] === 'object' ? containers[0] : undefined;
  } catch {
    return undefined;
  }
}

function envFromInspect(container, key) {
  const env = container?.Config?.Env;
  if (!Array.isArray(env)) return '';
  const prefix = `${key}=`;
  const entry = env.find((value) => String(value).startsWith(prefix));
  return entry ? String(entry).slice(prefix.length) : '';
}

function isPinnedIslandoraBlazegraph(container) {
  return String(container?.Config?.Image || '').startsWith('islandora/blazegraph:');
}

function blackboxDockerRunner(log) {
  return {
    async run(args, opts) {
      if (args[0] === 'run' && !args.some((arg) => String(arg).startsWith('TOMCAT_JAVA_OPTS='))) {
        return runDocker(
          [
            'run',
            '--cpus',
            BLACKBOX_BLAZEGRAPH_CPUS,
            '-e',
            `TOMCAT_JAVA_OPTS=${BLACKBOX_BLAZEGRAPH_JAVA_OPTS}`,
            ...args.slice(1),
          ],
          opts,
        );
      }

      const result = await runDocker([...args], opts);
      if (args[0] !== 'inspect' || result.exitCode !== 0) return result;

      const container = containerFromInspect(result.stdout);
      const javaOpts = envFromInspect(container, 'TOMCAT_JAVA_OPTS');
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
      if (!isPinnedIslandoraBlazegraph(container)) {
        throw new Error(
          `Existing Blazegraph container "${name}" does not expose a 4 GB effective Tomcat heap `
          + `and uses unsupported image "${container?.Config?.Image || 'unknown'}". `
          + 'Refusing to replace it because its local graph data may not be mounted durably.',
        );
      }

      if (container?.State?.Running !== true) {
        // The DKG provisioner will start stopped containers and inspect them again.
        // Repair only after that start so docker exec can update the image startup hook.
        return result;
      }

      const marker = await runDocker([
        'exec', '--user', '0', name, 'sh', '-c',
        `grep -Fq '${EFFECTIVE_HEAP_MARKER}' /opt/tomcat/bin/setenv.sh`,
      ], { timeoutMs: 10_000 });
      if (marker.exitCode !== 0) {
        log(
          `  Existing container "${name}" uses ${javaOpts || 'the image-default Tomcat heap'}; `
          + 'repairing it in place with a 4 GB heap while preserving /data.',
        );
        const patched = await runDocker(
          ['exec', '--user', '0', name, 'sh', '-c', LEGACY_HEAP_PATCH.join('; ')],
          { timeoutMs: 10_000 },
        );
        if (patched.exitCode !== 0) {
          throw new Error(
            `Could not repair the effective Blazegraph heap in container "${name}": `
            + `${patched.stderr.trim() || 'startup hook update failed'}. `
            + 'The existing container and graph data were left in place.',
          );
        }
        const restarted = await runDocker(['restart', name], { timeoutMs: 120_000 });
        if (restarted.exitCode !== 0) {
          throw new Error(
            `Could not restart Blazegraph container "${name}" after applying the 4 GB heap: `
            + `${restarted.stderr.trim() || 'docker restart failed'}`,
          );
        }
      }

      const limited = await runDocker(
        ['update', '--cpus', BLACKBOX_BLAZEGRAPH_CPUS, name],
        { timeoutMs: 10_000 },
      );
      if (limited.exitCode !== 0) {
        throw new Error(`Could not apply the Blackbox CPU limit to "${name}": ${limited.stderr.trim()}`);
      }
      return result;
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
