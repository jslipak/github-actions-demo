import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

const project = process.argv[2];
if (!project) throw new Error('Project directory is required');

const policy = JSON.parse(await readFile('.github/dependency-policy.json', 'utf8'));
const lock = JSON.parse(await readFile(join(project, 'package-lock.json'), 'utf8'));
const packages = Object.entries(lock.packages ?? {})
  .filter(([path, data]) => path.includes('node_modules/') && data.version)
  .map(([path, data]) => ({
    name: path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length),
    version: data.version,
    lockIntegrity: data.integrity,
    resolved: data.resolved,
  }));

const findings = [];
const published = new Map();
for (const dependency of packages) {
  if (dependency.resolved) {
    const resolvedHost = new URL(dependency.resolved).host;
    const approvedHost = new URL(policy.registry).host;
    if (resolvedHost !== approvedHost) {
      findings.push({ ...dependency, status: 'unapproved-registry', resolvedHost, approvedHost });
    }
  }
  let metadata;
  try {
    const output = execFileSync('npm', [
      'view', `${dependency.name}@${dependency.version}`,
      'dist.integrity', 'license', 'deprecated', '--json',
      `--registry=${policy.registry}`,
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    metadata = JSON.parse(output);
  } catch (error) {
    findings.push({ ...dependency, status: 'registry-query-failed', details: error.stderr?.toString() ?? error.message });
    continue;
  }

  const registryIntegrity = metadata['dist.integrity'];
  published.set(`${dependency.name}@${dependency.version}`, registryIntegrity);
  const license = metadata.license;
  const deprecated = metadata.deprecated;
  if (!registryIntegrity || (dependency.lockIntegrity && registryIntegrity !== dependency.lockIntegrity)) {
    findings.push({ ...dependency, status: 'integrity-mismatch', lockIntegrity: dependency.lockIntegrity, registryIntegrity });
  }
  if (license && !policy.allowedLicenses.includes(license)) {
    findings.push({ ...dependency, status: 'license-policy-violation', license });
  }
  if (deprecated) {
    findings.push({ ...dependency, status: 'deprecated-review', notice: deprecated });
  }
}

const artifactDirectory = join(project, 'artifacts');
try {
  for (const file of await readdir(artifactDirectory)) {
    if (!file.endsWith('.tgz')) continue;
    const match = file.match(/^(.+)-(\d+\.\d+\.\d+)(?:-[^.]+)?\.tgz$/);
    if (!match) {
      findings.push({ artifact: file, status: 'artifact-name-unrecognized' });
      continue;
    }
    const version = match[2];
    const packageName = match[1].replace(/^(@[^/]+)-/, '$1/');
    const expectedIntegrity = published.get(`${packageName}@${version}`);
    const data = await readFile(join(artifactDirectory, file));
    const actualIntegrity = `sha512-${createHash('sha512').update(data).digest('base64')}`;
    if (!expectedIntegrity || actualIntegrity !== expectedIntegrity) {
      findings.push({ artifact: file, package: packageName, version, status: 'artifact-integrity-mismatch', expectedIntegrity, actualIntegrity });
    }
  }
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}

await writeFile(join(project, 'dependency-metadata-report.json'), JSON.stringify({ project, policy, checkedDependencies: packages.length, findings }, null, 2));
for (const finding of findings) console.log(JSON.stringify(finding));
if (findings.some(({ status }) => ['registry-query-failed', 'integrity-mismatch', 'license-policy-violation', 'artifact-integrity-mismatch', 'unapproved-registry'].includes(status))) {
  process.exitCode = 1;
}
