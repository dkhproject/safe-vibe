import { hasBlockingIssues } from './rules.js';

/**
 * Determines whether ANSI color codes should be emitted.
 * Respects NO_COLOR, FORCE_COLOR, and TTY status.
 *
 * @param {{ env?: Record<string, string | undefined>, isTTY?: boolean }} [options]
 * @returns {boolean}
 */
export function shouldUseColor({ env = process.env, isTTY = process.stdout.isTTY } = {}) {
  if (env.NO_COLOR) {
    return false;
  }
  if (env.FORCE_COLOR !== undefined && env.FORCE_COLOR !== '' && env.FORCE_COLOR !== '0') {
    return true;
  }
  return Boolean(isTTY);
}

function createPalette(enabled) {
  if (!enabled) {
    const id = (s) => s;
    return { bold: id, dim: id, red: id, yellow: id, cyan: id, green: id };
  }
  return {
    bold: (s) => `\x1b[1m${s}\x1b[0m`,
    dim: (s) => `\x1b[2m${s}\x1b[0m`,
    red: (s) => `\x1b[31m${s}\x1b[0m`,
    yellow: (s) => `\x1b[33m${s}\x1b[0m`,
    cyan: (s) => `\x1b[36m${s}\x1b[0m`,
    green: (s) => `\x1b[32m${s}\x1b[0m`,
  };
}

function formatSeverityBadge(severity, palette) {
  const label = severity.toUpperCase();
  if (severity === 'critical') {
    return palette.bold(palette.red(`[${label}]`));
  }
  if (severity === 'high') {
    return palette.bold(palette.yellow(`[${label}]`));
  }
  return palette.cyan(`[${label}]`);
}

function formatSeverityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0 };
  for (const finding of findings) {
    if (Object.hasOwn(counts, finding.severity)) {
      counts[finding.severity] += 1;
    }
  }
  const parts = [];
  for (const level of ['critical', 'high', 'medium']) {
    if (counts[level] > 0) {
      parts.push(`${counts[level]} ${level}`);
    }
  }
  return parts.join(', ');
}

/**
 * Formats audit findings into a human-readable (and optionally ANSI-colored) report.
 *
 * @param {Array<{ ruleId: string, category: string, severity: string, message: string, tip?: string, file: string, line: number, content: string }>} findings
 * @param {{ scannedLineCount?: number, unstaged?: boolean, strict?: boolean, color?: boolean }} [options]
 * @returns {string}
 */
export function formatReport(
  findings,
  { scannedLineCount = 0, unstaged = false, strict = false, color } = {}
) {
  const useColor = color ?? shouldUseColor();
  const palette = createPalette(useColor);
  const scope = unstaged ? 'unstaged' : 'staged';

  if (findings.length === 0) {
    const scopeInfo =
      scannedLineCount === 0
        ? `no added ${scope} lines`
        : `audited ${scannedLineCount} added ${scope} line(s)`;
    return palette.green(`✔ Safe to commit — no vibe-coding traps found (${scopeInfo})`);
  }

  const lines = [];
  lines.push(
    palette.bold(
      `safe-vibe: Found ${findings.length} issue(s) across ${scannedLineCount} added ${scope} line(s):`
    )
  );
  lines.push('');

  for (const finding of findings) {
    const badge = formatSeverityBadge(finding.severity, palette);
    const location = palette.bold(`${finding.file}:${finding.line}`);
    const rule = palette.dim(`(${finding.ruleId})`);
    lines.push(`${badge} ${location} ${rule}`);
    lines.push(`  ${finding.message}`);
    lines.push(`  ${palette.dim(`> ${finding.content.trim()}`)}`);
    if (finding.tip) {
      lines.push(`  ${palette.cyan(`Tip: ${finding.tip}`)}`);
    }
    lines.push('');
  }

  const blocking = hasBlockingIssues(findings, { strict });
  if (blocking) {
    const countSummary = formatSeverityCounts(findings);
    lines.push(
      palette.bold(palette.red(`✖ Commit blocked by safe-vibe (${countSummary})`))
    );
  } else {
    const mediumCount = findings.filter((f) => f.severity === 'medium').length;
    lines.push(
      palette.green(
        `✔ Safe to commit — no blocking traps found (${mediumCount} medium warning${mediumCount === 1 ? '' : 's'})`
      )
    );
  }

  return lines.join('\n');
}

/**
 * Prints the formatted audit report to stdout.
 *
 * @param {Array} findings
 * @param {object} [options]
 */
export function printReport(findings, options = {}) {
  console.log(formatReport(findings, options));
}
