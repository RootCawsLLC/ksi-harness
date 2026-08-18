import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Fixture loading, shared by every collector family.
 *
 * A fixture is a directory; each check reads its own file from it. That lets one `--fixture`
 * flag drive a whole offline run, and it means a check with no fixture present says so
 * rather than reporting an empty population as a pass.
 */
export function loadFixture(fixtureDir, basename, { json = true } = {}) {
  if (!existsSync(fixtureDir) || !statSync(fixtureDir).isDirectory()) {
    throw new Error(`Fixture path "${fixtureDir}" is not a directory. Pass the directory holding the fixture files.`);
  }
  const path = join(fixtureDir, `${basename}.${json ? 'json' : 'csv'}`);
  if (!existsSync(path)) {
    throw new Error(
      `No fixture for ${basename} at ${path}. A check without a fixture cannot be run offline; ` +
        `add one or run against real credentials.`
    );
  }
  const raw = readFileSync(path, 'utf8');
  return json ? JSON.parse(raw) : raw;
}

/**
 * Marks a bundle's scope so fixture output can never be mistaken for real evidence.
 *
 * The string is loud on purpose. Evidence bundles get copied into decks and tickets, and a
 * fixture run that reads as real is a worse outcome than a failed run.
 */
export function fixtureScope(fixtureDir, basename, extra = {}) {
  return {
    account: 'fixture',
    source: `FIXTURE ${fixtureDir}/${basename} - NOT REAL EVIDENCE`,
    fixture: true,
    ...extra,
  };
}
