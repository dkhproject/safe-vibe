#!/usr/bin/env node

import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { getAddedLines } from '../src/diffParser.js';
import { auditLines, hasBlockingIssues } from '../src/rules.js';
import { installHook, uninstallHook } from '../src/hookManager.js';
import { printReport } from '../src/reporter.js';

const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const USAGE = `safe-vibe — Audit newly added git diff lines for AI-generated security & logic pitfalls

Usage:
  safe-vibe [options]
  safe-vibe install
  safe-vibe uninstall

Commands:
  install          Install the safe-vibe pre-commit hook in .git/hooks/pre-commit
  uninstall        Remove the safe-vibe pre-commit hook block cleanly

Options:
  -u, --unstaged   Audit unstaged working tree changes (git diff -U0) instead of staged changes
      --strict     Treat medium severity issues (TODO: implement / FIXME) as blocking
      --json       Output audit results as JSON
  -v, --version    Show version number
  -h, --help       Show this help message

Exit codes:
  0  No blocking issues found (or hook command succeeded)
  1  One or more blocking issues found, invalid usage, or execution error
`;

function main() {
  let values;
  let positionals;
  try {
    ({ values, positionals } = parseArgs({
      options: {
        unstaged: { type: 'boolean', short: 'u', default: false },
        strict: { type: 'boolean', default: false },
        json: { type: 'boolean', default: false },
        version: { type: 'boolean', short: 'v', default: false },
        help: { type: 'boolean', short: 'h', default: false },
      },
      strict: true,
      allowPositionals: true,
    }));
  } catch (err) {
    console.error(`safe-vibe: ${err.message}`);
    console.error('Run "safe-vibe --help" for usage.');
    process.exit(1);
  }

  if (values.help) {
    process.stdout.write(USAGE);
    process.exit(0);
  }

  if (values.version) {
    console.log(`safe-vibe v${pkg.version}`);
    process.exit(0);
  }

  if (positionals.length > 0) {
    if (positionals.length > 1) {
      console.error(`safe-vibe: Unexpected arguments: ${positionals.join(' ')}`);
      console.error('Run "safe-vibe --help" for usage.');
      process.exit(1);
    }

    const command = positionals[0];
    try {
      if (command === 'install') {
        const result = installHook();
        console.log(result.message);
        process.exit(0);
      }
      if (command === 'uninstall') {
        const result = uninstallHook();
        console.log(result.message);
        process.exit(0);
      }
      console.error(`safe-vibe: Unknown command "${command}".`);
      console.error('Run "safe-vibe --help" for usage.');
      process.exit(1);
    } catch (err) {
      console.error(`safe-vibe error: ${err.message}`);
      process.exit(1);
    }
  }

  try {
    const addedLines = getAddedLines({ unstaged: values.unstaged });
    const findings = auditLines(addedLines);
    const blocking = hasBlockingIssues(findings, { strict: values.strict });

    if (values.json) {
      console.log(JSON.stringify({ findings, blocking }, null, 2));
    } else {
      printReport(findings, {
        scannedLineCount: addedLines.length,
        unstaged: values.unstaged,
        strict: values.strict,
      });
    }

    process.exit(blocking ? 1 : 0);
  } catch (err) {
    console.error(`safe-vibe error: ${err.message}`);
    process.exit(1);
  }
}

main();
