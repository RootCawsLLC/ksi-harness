import { readFileSync } from 'node:fs';

import { parse } from 'yaml';

/**
 * The profile fixture runs use: the same one `npm run collect:fixture` and the demo use.
 *
 * Fixture runs used to pass `{}`, which meant nothing while every collector ran regardless. Now a
 * provider without a section is outside the boundary and its collectors are skipped, so `{}`
 * would quietly run only the unscoped families, and every test iterating "all the bundles" would
 * keep passing over a fraction of them. Declaring every provider is what makes those tests mean
 * what they say.
 */
export const FIXTURE_PROFILE = Object.freeze(parse(readFileSync('examples/northwind.profile.yaml', 'utf8')));
