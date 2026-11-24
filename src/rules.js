export const INLINE_IGNORE_REGEX = /(?:\/\/|#)\s*safe-vibe-ignore\b/;

export const BLOCKING_SEVERITIES = new Set(['critical', 'high']);
export const STRICT_BLOCKING_SEVERITIES = new Set(['critical', 'high', 'medium']);

const SPECIFIC_SECRET_RULES = [
  {
    ruleId: 'secret-aws-access-key',
    category: 'secrets',
    severity: 'critical',
    message: 'Potential hardcoded AWS access key ID detected',
    tip: 'Move AWS credentials to environment variables or IAM roles and rotate exposed keys immediately.',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  },
  {
    ruleId: 'secret-github-token',
    category: 'secrets',
    severity: 'critical',
    message: 'Potential hardcoded GitHub personal access token detected',
    tip: 'Store GitHub tokens in environment variables or a secrets manager, and revoke exposed tokens.',
    regex: /\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b/,
  },
  {
    ruleId: 'secret-anthropic-key',
    category: 'secrets',
    severity: 'critical',
    message: 'Potential hardcoded Anthropic API key detected',
    tip: 'Load Anthropic API keys from process.env or a secrets manager rather than source code.',
    regex: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    ruleId: 'secret-openai-key',
    category: 'secrets',
    severity: 'critical',
    message: 'Potential hardcoded OpenAI API key detected',
    tip: 'Load OpenAI API keys from process.env or a secrets manager rather than source code.',
    regex: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    ruleId: 'secret-private-key',
    category: 'secrets',
    severity: 'critical',
    message: 'Hardcoded private key header detected',
    tip: 'Store private keys outside the repository (e.g., secrets manager or mounted files) and rotate if exposed.',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
  },
];

const GENERIC_SECRET_ASSIGNMENT_REGEX =
  /(?:^|[\s,{.[("'`])(?:[A-Za-z0-9_$-]*?(?:api_?key|secret|password|passwd|auth_?token|access_?token|private_?key|client_?secret))['"`]?\s*(?:=(?!=)|:)\s*(['"`])([^'"`\\]*(?:\\.[^'"`\\]*)*)\1/gi;

const SINGLE_LINE_EMPTY_CATCH_REGEX =
  /\bcatch\s*(?:\([^)]*\))?\s*\{\s*(?:\/\*[\s\S]*?\*\/\s*|;)?\s*\}/;
const MULTILINE_CATCH_OPEN_REGEX =
  /\bcatch\s*(?:\([^)]*\))?\s*\{\s*(?:\/\/.*|\/\*.*\*\/)?\s*$/;
const MULTILINE_CATCH_CLOSE_REGEX =
  /^\s*\}\s*(?:\/\/.*|\/\*.*\*\/)?\s*$/;

const SINGLE_LINE_EMPTY_EXCEPT_REGEX =
  /\bexcept\b[^:]*:\s*(?:pass\b|\.\.\.(?:\s*(?:#.*)?$))/;
const MULTILINE_EXCEPT_OPEN_REGEX = /^\s*except\b[^:]*:\s*(?:#.*)?$/;
const MULTILINE_EXCEPT_BODY_REGEX = /^\s*(?:pass\b|\.\.\.)\s*(?:#.*)?$/;

const JS_BLANK_OR_COMMENT_REGEX = /^\s*(?:\/\/.*|\/\*[\s\S]*?\*\/)?\s*$/;
const PY_BLANK_OR_COMMENT_REGEX = /^\s*(?:#.*)?$/;

const INJECTION_RULES = [
  {
    ruleId: 'dangerous-eval',
    category: 'injection',
    severity: 'critical',
    message: 'Use of eval() enables arbitrary code execution',
    tip: 'Replace eval() with safe parsing (e.g., JSON.parse) or explicit dispatch tables.',
    regex: /(?:^|[^\w$.])(?:(?:window|globalThis|global)\.)?eval\s*\(/,
  },
  {
    ruleId: 'dangerous-new-function',
    category: 'injection',
    severity: 'critical',
    message: 'Use of new Function() enables arbitrary code execution',
    tip: 'Avoid dynamic code generation with new Function(); use static functions or safe data-driven logic.',
    regex: /\bnew\s+Function\s*\(/,
  },
  {
    ruleId: 'dangerous-exec-template',
    category: 'injection',
    severity: 'critical',
    message: 'child_process exec/execSync with template interpolation risks command injection',
    tip: 'Use execFile/spawn with an argument array instead of interpolating variables into a shell string.',
    regex: /\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`/,
  },
  {
    ruleId: 'dangerous-inner-html',
    category: 'injection',
    severity: 'high',
    message: 'dangerouslySetInnerHTML risks cross-site scripting (XSS)',
    tip: 'Render safe JSX elements or sanitize untrusted HTML with a strict sanitizer first.',
    regex: /\bdangerouslySetInnerHTML\b/,
  },
];

const SQL_STATEMENT_REGEX =
  /\b(?:SELECT\b[\s\S]*?\bFROM\b|INSERT\s+INTO\b|UPDATE\b[\s\S]*?\bSET\b|DELETE\s+FROM\b)/i;
const TEMPLATE_LITERAL_WITH_INTERP_REGEX = /`([^`]*\$\{[^}]+\}[^`]*)`/g;
const QUOTED_STRING_LITERAL_REGEX = /(['"])((?:\\.|(?!\1).)*)\1/g;

const DEBRIS_RULES = [
  {
    ruleId: 'debris-placeholder',
    category: 'debris',
    severity: 'medium',
    message: 'Leftover placeholder comment (TODO: implement / FIXME)',
    tip: 'Finish the placeholder implementation or track it in an issue before shipping.',
    regex: /\b(?:TODO\s*:?\s*implement\b|FIXME\b)/i,
  },
  {
    ruleId: 'debris-sensitive-log',
    category: 'debris',
    severity: 'high',
    message: 'console logging appears to reference sensitive credentials or tokens',
    tip: 'Remove sensitive credential fields from log statements or redact them before logging.',
    regex:
      /\bconsole\.(?:log|debug|info|warn|error)\s*\([^)]*\b[a-z0-9_-]*(?:token|password|passwd|secret|api[_-]?key|private[_-]?key|credentials?)\b/i,
  },
];

/**
 * Calculates Shannon entropy (bits per character) for a string.
 * @param {string} str
 * @returns {number}
 */
export function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const counts = new Map();
  for (const ch of str) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Returns true if a string looks like an obvious placeholder, template, or dummy value.
 * @param {string} value
 * @returns {boolean}
 */
export function isPlaceholderSecret(value) {
  if (!value || value.length < 12) return true;
  if (/\$\{|\{\{|process\.env\b|os\.environ\b|<[^>]+>/i.test(value)) {
    return true;
  }
  if (/^(?:x+|[*]+|\.+|-+|_+)$/i.test(value)) {
    return true;
  }
  if (/(?:changeme|placeholder|example|your_|dummy|test|fake|replace[_-]?me|insert[_-]?here)/i.test(value)) {
    return true;
  }
  return false;
}

/**
 * Checks whether a line contains raw SQL built via template interpolation or `+` concatenation.
 * @param {string} content
 * @returns {boolean}
 */
function hasRawSqlInjection(content) {
  TEMPLATE_LITERAL_WITH_INTERP_REGEX.lastIndex = 0;
  let tmplMatch;
  while ((tmplMatch = TEMPLATE_LITERAL_WITH_INTERP_REGEX.exec(content)) !== null) {
    if (SQL_STATEMENT_REGEX.test(tmplMatch[1])) {
      return true;
    }
  }

  QUOTED_STRING_LITERAL_REGEX.lastIndex = 0;
  let strMatch;
  while ((strMatch = QUOTED_STRING_LITERAL_REGEX.exec(content)) !== null) {
    const inner = strMatch[2];
    if (!SQL_STATEMENT_REGEX.test(inner)) {
      continue;
    }

    const before = content.slice(0, strMatch.index);
    const after = content.slice(strMatch.index + strMatch[0].length);

    // Check `sql + nonLiteral` on the right side.
    const rightConcat = /^\s*\+\s*(.+)$/.exec(after);
    if (rightConcat) {
      const rhs = rightConcat[1].trim();
      if (rhs.length > 0 && !/^['"`]/.test(rhs)) {
        return true;
      }
    }

    // Check `nonLiteral + sql` on the left side.
    const leftConcat = /^(.*)\+\s*$/.exec(before);
    if (leftConcat) {
      const lhs = leftConcat[1].trimEnd();
      if (lhs.length > 0 && !/['"`]$/.test(lhs)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Detects multi-line empty catch or Python except blocks across consecutive added lines.
 * @param {Array<{ file: string, line: number, content: string }>} addedLines
 * @param {number} startIndex
 * @param {RegExp} openRegex
 * @param {RegExp} blankOrCommentRegex
 * @param {RegExp} closeRegex
 * @returns {boolean}
 */
function matchesMultilineEmptyBlock(
  addedLines,
  startIndex,
  openRegex,
  blankOrCommentRegex,
  closeRegex
) {
  const start = addedLines[startIndex];
  if (!openRegex.test(start.content)) {
    return false;
  }
  if (INLINE_IGNORE_REGEX.test(start.content)) {
    return false;
  }

  let prevLineNum = start.line;
  for (let j = startIndex + 1; j < addedLines.length; j += 1) {
    const next = addedLines[j];
    if (next.file !== start.file || next.line !== prevLineNum + 1) {
      return false;
    }
    prevLineNum = next.line;

    if (INLINE_IGNORE_REGEX.test(next.content)) {
      return false;
    }
    if (closeRegex.test(next.content)) {
      return true;
    }
    if (!blankOrCommentRegex.test(next.content)) {
      return false;
    }
  }

  return false;
}

/**
 * Audits newly added diff lines against security, error-handling, injection, and debris rules.
 *
 * @param {Array<{ file: string, line: number, content: string }>} addedLines
 * @returns {Array<{ ruleId: string, category: string, severity: string, message: string, tip: string, file: string, line: number, content: string }>}
 */
export function auditLines(addedLines) {
  if (!Array.isArray(addedLines) || addedLines.length === 0) {
    return [];
  }

  const findings = [];

  for (let i = 0; i < addedLines.length; i += 1) {
    const entry = addedLines[i];
    const { file, line, content } = entry;

    if (INLINE_IGNORE_REGEX.test(content)) {
      continue;
    }

    // 1. Hardcoded secrets & API keys
    let matchedSpecificSecret = false;
    for (const rule of SPECIFIC_SECRET_RULES) {
      if (rule.regex.test(content)) {
        matchedSpecificSecret = true;
        findings.push({
          ruleId: rule.ruleId,
          category: rule.category,
          severity: rule.severity,
          message: rule.message,
          tip: rule.tip,
          file,
          line,
          content,
        });
      }
    }

    if (!matchedSpecificSecret) {
      GENERIC_SECRET_ASSIGNMENT_REGEX.lastIndex = 0;
      let secretMatch;
      while ((secretMatch = GENERIC_SECRET_ASSIGNMENT_REGEX.exec(content)) !== null) {
        const value = secretMatch[2];
        if (
          value.length >= 12 &&
          !isPlaceholderSecret(value) &&
          shannonEntropy(value) >= 3.2
        ) {
          findings.push({
            ruleId: 'secret-generic-assignment',
            category: 'secrets',
            severity: 'critical',
            message: 'Potential hardcoded high-entropy secret or credential assignment detected',
            tip: 'Move hardcoded secrets to environment variables (e.g., process.env) or a secret store.',
            file,
            line,
            content,
          });
          break;
        }
      }
    }

    // 2. Silent error swallowing
    if (
      SINGLE_LINE_EMPTY_CATCH_REGEX.test(content) ||
      matchesMultilineEmptyBlock(
        addedLines,
        i,
        MULTILINE_CATCH_OPEN_REGEX,
        JS_BLANK_OR_COMMENT_REGEX,
        MULTILINE_CATCH_CLOSE_REGEX
      )
    ) {
      findings.push({
        ruleId: 'silent-empty-catch',
        category: 'error-handling',
        severity: 'high',
        message: 'Empty catch block silently swallows errors',
        tip: 'Log, rethrow, or explicitly handle the caught error instead of leaving catch empty.',
        file,
        line,
        content,
      });
    }

    if (
      SINGLE_LINE_EMPTY_EXCEPT_REGEX.test(content) ||
      matchesMultilineEmptyBlock(
        addedLines,
        i,
        MULTILINE_EXCEPT_OPEN_REGEX,
        PY_BLANK_OR_COMMENT_REGEX,
        MULTILINE_EXCEPT_BODY_REGEX
      )
    ) {
      findings.push({
        ruleId: 'silent-empty-except',
        category: 'error-handling',
        severity: 'high',
        message: 'Empty Python except block silently swallows errors',
        tip: 'Log, re-raise, or handle the exception instead of swallowing it with pass or ... .',
        file,
        line,
        content,
      });
    }

    // 3. Dangerous execution & injection risks
    for (const rule of INJECTION_RULES) {
      if (rule.regex.test(content)) {
        findings.push({
          ruleId: rule.ruleId,
          category: rule.category,
          severity: rule.severity,
          message: rule.message,
          tip: rule.tip,
          file,
          line,
          content,
        });
      }
    }

    if (hasRawSqlInjection(content)) {
      findings.push({
        ruleId: 'dangerous-raw-sql',
        category: 'injection',
        severity: 'critical',
        message: 'Raw SQL string interpolation or concatenation risks SQL injection',
        tip: 'Use parameterized queries or prepared statements ($1, ?) instead of interpolating variables into SQL.',
        file,
        line,
        content,
      });
    }

    // 4. Leftover AI debug/placeholder debris
    for (const rule of DEBRIS_RULES) {
      if (rule.regex.test(content)) {
        findings.push({
          ruleId: rule.ruleId,
          category: rule.category,
          severity: rule.severity,
          message: rule.message,
          tip: rule.tip,
          file,
          line,
          content,
        });
      }
    }
  }

  return findings;
}

/**
 * Returns true if any finding has a blocking severity.
 * By default blocks on critical and high; when strict is true, also blocks on medium.
 *
 * @param {Array<{ severity: string }>} findings
 * @param {{ strict?: boolean }} [options]
 * @returns {boolean}
 */
export function hasBlockingIssues(findings, { strict = false } = {}) {
  const severities = strict ? STRICT_BLOCKING_SEVERITIES : BLOCKING_SEVERITIES;
  return findings.some((finding) => severities.has(finding.severity));
}
