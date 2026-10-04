// Packs every workspace package into ./artifacts (cross-platform).
import { mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

mkdirSync('artifacts', { recursive: true });
const r = spawnSync('npm pack --workspaces --pack-destination artifacts', { stdio: 'inherit', shell: true });
process.exit(r.status ?? 1);
