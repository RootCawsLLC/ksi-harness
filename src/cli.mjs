#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { parse } from 'yaml';

import { catalog, resolveIndicator, termsFor } from './catalog/ksi.mjs';
import { rulesProvenance } from './catalog/rules.mjs';
import { runAll } from './collectors/run-all.mjs';
import { ALL_CHECKS } from './collectors/registry.mjs';
import { buildState } from './evidence/state.mjs';
import { emitterFor, EMITTERS } from './emit/index.mjs';
import { coverageJson, coverageMarkdown, coverageText } from './report/coverage.mjs';
import { checkDrift, driftMarkdown } from './report/drift.mjs';
import { loadRoutes, validateRoutes } from './routes/routes.mjs';

/**
 * Command line entry point.
 *
 * Exit codes are load-bearing, because this runs in CI: 0 clean, 1 a failure the operator must
 * act on, 2 a usage error. In particular `collect` exits non-zero when a collector could not
 * run at all, so a credentials problem cannot pass as a quiet, evidence-free success.
 */

function args(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const [key, inline] = token.slice(2).split('=');
      if (inline !== undefined) flags[key] = inline;
      else if (argv[i + 1] && !argv[i + 1].startsWith('--')) flags[key] = argv[++i];
      else flags[key] = true;
    } else positional.push(token);
  }
  return { flags, positional };
}

const readProfile = (path) => {
  if (!path) throw new Error('--profile is required (see examples/northwind.profile.yaml)');
  return parse(readFileSync(path, 'utf8'));
};

function write(path, contents) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents, 'utf8');
  return path;
}

const USAGE = `ksi-harness — continuous control monitoring for FedRAMP 20x

  ksi catalog [--class c] [--theme IAM] [--json]
      The Key Security Indicator catalog resolved for a certification class.

  ksi explain KSI-IAM-APM [--class c]
      One indicator: statement, FedRAMP-defined terms, 800-53 mappings, and how it is routed.

  ksi checks
      Every implemented check and the indicators that claim it.

  ksi routes validate [--class c]
      Validate the routing map against the catalog and the check registry.

  ksi collect --profile F [--fixture DIR] [--out DIR] [--only aws|check.id]
      Run the collectors and write evidence bundles.

  ksi coverage [--evidence DIR] [--class c] [--md FILE] [--json FILE] [--fail-on-findings]
      The coverage report.

  ksi emit KIND --overview-uri URI [--evidence DIR] [--out FILE] [--base-uri URI]
      Emit an artifact. KIND: ${Object.keys(EMITTERS).join(' | ')}

  ksi drift [--md FILE]
      Compare the pinned ruleset against upstream and name the routes affected.
`;

async function main() {
  const { flags, positional } = args(process.argv.slice(2));
  const [command, sub] = positional;
  const klass = flags.class ?? 'c';
  const evidenceDir = flags.evidence ?? '.evidence';

  switch (command) {
    case undefined:
    case 'help':
      process.stdout.write(USAGE);
      return 0;

    case 'catalog': {
      const resolved = catalog({ klass });
      const filtered = flags.theme
        ? resolved.indicators.filter((i) => i.theme === String(flags.theme).toUpperCase())
        : resolved.indicators;
      if (flags.json) {
        process.stdout.write(`${JSON.stringify({ ...resolved, indicators: filtered }, null, 2)}\n`);
        return 0;
      }
      const p = rulesProvenance();
      console.log(`${p.title}\nversion ${p.version} (updated ${p.last_updated})  sha256:${p.sha256.slice(0, 16)}`);
      console.log(
        `\nClass ${klass.toUpperCase()}: ${resolved.counts.applicable} applicable of ${resolved.counts.total} — ` +
          `${resolved.counts.mandatory} mandatory, ${resolved.counts.optional} optional\n`
      );
      let theme = null;
      for (const i of filtered) {
        if (i.theme !== theme) {
          theme = i.theme;
          console.log(`${theme} — ${i.theme_name}`);
        }
        const mark = !i.applicable ? '  n/a' : i.optional ? '  opt' : '     ';
        console.log(`${mark} ${i.id}  ${i.name}  [${i.controls.length} controls]`);
      }
      return 0;
    }

    case 'explain': {
      const id = sub;
      if (!id) throw new Error('Usage: ksi explain KSI-IAM-APM');
      const indicator = resolveIndicator(id, { klass });
      const route = loadRoutes()[id];
      console.log(`${indicator.id} — ${indicator.name}   [theme ${indicator.theme}: ${indicator.theme_name}]\n`);
      console.log(`${indicator.statement ?? '(does not apply at this class)'}\n`);
      console.log(`applicable at Class ${klass.toUpperCase()}: ${indicator.applicable}   optional: ${indicator.optional}`);
      console.log(`  basis: ${indicator.optional_basis}\n`);

      const terms = termsFor(id);
      if (terms.length) {
        console.log('FedRAMP-defined terms this indicator relies on:');
        for (const term of terms) {
          console.log(`  ${term.term} (${term.id ?? 'undefined'})`);
          if (term.definition) console.log(`    ${term.definition.replace(/\s+/g, ' ').slice(0, 160)}…`);
        }
        console.log('');
      }

      console.log(`NIST 800-53 controls (${indicator.controls.length}): ${indicator.controls.join(', ')}\n`);

      if (!route) {
        console.log('No route declared.');
        return 1;
      }
      console.log(`coverage: ${route.coverage}   cadence: ${route.cadence ?? '—'}`);
      if (route.checks?.length) console.log(`checks: ${route.checks.join(', ')}`);
      if (route.sufficiency) console.log(`\nsufficiency argument:\n  ${route.sufficiency.trim().replace(/\s+/g, ' ')}`);
      if (route.unautomated?.length) {
        console.log('\nnot established by automation:');
        for (const gap of route.unautomated) console.log(`  - ${gap.trim().replace(/\s+/g, ' ')}`);
      }
      if (route.manual_evidence) {
        console.log(`\nmanual: owner ${route.manual_evidence.owner}`);
        console.log(`  artifact: ${route.manual_evidence.artifact}`);
        console.log(`  why not automated: ${route.manual_evidence.why_not_automated.trim().replace(/\s+/g, ' ')}`);
      }
      if (route.reason) console.log(`\nreason unaddressed: ${route.reason.trim().replace(/\s+/g, ' ')}`);
      if (route.next) console.log(`next: ${route.next.trim().replace(/\s+/g, ' ')}`);
      return 0;
    }

    case 'checks': {
      const routes = loadRoutes();
      console.log(`${ALL_CHECKS.length} implemented check(s)\n`);
      for (const check of ALL_CHECKS) {
        const claimedBy = Object.values(routes)
          .filter((r) => r.checks?.includes(check.id))
          .map((r) => r.id);
        console.log(`${check.id}   v${check.version}`);
        console.log(`  ${check.path}`);
        console.log(`  declares: ${check.ksis.join(', ')}`);
        console.log(`  claimed by: ${claimedBy.length ? claimedBy.join(', ') : 'NOTHING — evidence collected for no route'}`);
        console.log(`  asserts: ${check.assertion}\n`);
      }
      return 0;
    }

    case 'routes': {
      if (sub !== 'validate') throw new Error('Usage: ksi routes validate');
      const result = validateRoutes({ klass });
      for (const err of result.errors) console.error(`error   ${err}`);
      for (const warn of result.warnings) console.warn(`warning ${warn}`);
      console.log(
        result.ok
          ? `Routing map valid for Class ${klass.toUpperCase()} (${result.warnings.length} warning(s)).`
          : `Routing map invalid: ${result.errors.length} error(s).`
      );
      return result.ok ? 0 : 1;
    }

    case 'collect': {
      const profile = readProfile(flags.profile);
      const result = await runAll({
        profile,
        fixture: flags.fixture === true ? 'fixtures/collectors' : flags.fixture,
        outDir: flags.out ?? evidenceDir,
        sourceCommit: process.env.GITHUB_SHA ?? undefined,
        only: flags.only ? String(flags.only).split(',') : null,
        log: (line) => console.log(line),
      });
      console.log(
        `\n${result.bundles.length} bundle(s) written to ${flags.out ?? evidenceDir}; ${result.failures.length} collector failure(s).`
      );
      // A collector that could not run has produced no evidence. Exiting 0 here would let a
      // credentials failure look like a clean collection.
      return result.failures.length ? 1 : 0;
    }

    case 'coverage': {
      const profile = flags.profile ? readProfile(flags.profile) : null;
      const state = buildState({ evidenceDir, klass, profile });
      if (flags.md) console.log(`wrote ${write(String(flags.md), coverageMarkdown(state))}`);
      if (flags.json) console.log(`wrote ${write(String(flags.json), `${JSON.stringify(coverageJson(state), null, 2)}\n`)}`);
      if (!flags.md && !flags.json) console.log(coverageText(state));
      if (!state.routes_valid) return 1;
      if (flags['fail-on-findings']) {
        const failing = state.indicators.filter((i) => i.evidence_state === 'failing').length;
        if (failing) {
          console.error(`\n${failing} indicator(s) have failing evidence.`);
          return 1;
        }
      }
      return 0;
    }

    case 'emit': {
      const kind = sub;
      if (!kind) throw new Error(`Usage: ksi emit ${Object.keys(EMITTERS).join('|')} --overview-uri URI`);
      const emitter = emitterFor(kind);
      const profile = flags.profile ? readProfile(flags.profile) : null;
      const state = buildState({ evidenceDir, klass, profile });

      if (!state.routes_valid) {
        console.error('Refusing to emit: the routing map does not validate. Run `ksi routes validate`.');
        return 1;
      }

      const document = emitter.emit(state, {
        overviewUri: flags['overview-uri'] === true ? undefined : flags['overview-uri'],
        baseUri: flags['base-uri'] === true ? null : flags['base-uri'],
        title: flags.title === true ? undefined : flags.title,
      });
      const serialised = `${JSON.stringify(document, null, 2)}\n`;
      if (flags.out) console.log(`wrote ${write(String(flags.out), serialised)}`);
      else process.stdout.write(serialised);
      if (flags.out) {
        console.log(
          emitter.validated
            ? `${emitter.label} — validated against the vendored FedRAMP schema.`
            : `${emitter.label} — not schema-validated here; validate with oscal-cli.`
        );
      }
      return 0;
    }

    case 'drift': {
      const diff = await checkDrift();
      if (flags.md) console.log(`wrote ${write(String(flags.md), driftMarkdown(diff))}`);
      else process.stdout.write(driftMarkdown(diff));
      return diff.ok ? 0 : 1;
    }

    default:
      process.stderr.write(`Unknown command "${command}".\n\n${USAGE}`);
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
