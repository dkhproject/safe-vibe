import { execFileSync } from 'node:child_process';
import path from 'node:path';

const KNOWN_LOCKFILES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'bun.lock',
  'Cargo.lock',
  'Gemfile.lock',
  'poetry.lock',
  'Pipfile.lock',
  'composer.lock',
  'go.sum',
  'flake.lock',
  'uv.lock',
  'shrinkwrap.yaml',
  'npm-shrinkwrap.json',
]);

const HUNK_HEADER_REGEX = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/**
 * Returns true if the given file path refers to a dependency lockfile.
 * @param {string} filePath
 * @returns {boolean}
 */
export function isLockfile(filePath) {
  if (!filePath) return false;
  const base = path.posix.basename(filePath.replace(/\\/g, '/'));
  return KNOWN_LOCKFILES.has(base) || base.endsWith('.lock');
}

/**
 * Extracts the target file path from a `+++ ` diff header line.
 * @param {string} headerLine
 * @returns {string | null}
 */
function parseTargetFileHeader(headerLine) {
  let rawPath = headerLine.slice(4).trim();
  if (rawPath === '/dev/null') {
    return null;
  }
  if (rawPath.startsWith('"') && rawPath.endsWith('"') && rawPath.length >= 2) {
    rawPath = rawPath.slice(1, -1);
  }
  if (rawPath.startsWith('b/')) {
    return rawPath.slice(2);
  }
  return rawPath;
}

/**
 * Parses unified diff output and returns only newly added (`+`) lines
 * along with their target file path and 1-based target line number.
 * Skips deleted files, lockfiles, and binary files.
 *
 * @param {string} diffText
 * @returns {Array<{ file: string, line: number, content: string }>}
 */
export function parseDiff(diffText) {
  if (!diffText) return [];

  const results = [];
  const lines = diffText.split(/\r?\n/);

  let currentFile = null;
  let skipFile = false;
  let inHunk = false;
  let currentLine = 0;
  let oldRemaining = 0;
  let newRemaining = 0;

  for (const rawLine of lines) {
    if (rawLine.startsWith('diff --git ')) {
      currentFile = null;
      skipFile = false;
      inHunk = false;
      oldRemaining = 0;
      newRemaining = 0;
      continue;
    }

    const atHunkBoundary = !inHunk || (oldRemaining <= 0 && newRemaining <= 0);

    if (atHunkBoundary && rawLine.startsWith('--- ')) {
      inHunk = false;
      continue;
    }

    if (atHunkBoundary && rawLine.startsWith('+++ ')) {
      inHunk = false;
      const parsedFile = parseTargetFileHeader(rawLine);
      if (parsedFile === null) {
        currentFile = null;
        skipFile = true;
      } else {
        currentFile = parsedFile;
        if (isLockfile(currentFile)) {
          skipFile = true;
        }
      }
      continue;
    }

    if (!inHunk) {
      if (
        rawLine.startsWith('deleted file mode ') ||
        rawLine === 'GIT binary patch' ||
        /^Binary files .* differ$/.test(rawLine)
      ) {
        skipFile = true;
        continue;
      }
    }

    const hunkMatch = HUNK_HEADER_REGEX.exec(rawLine);
    if (hunkMatch) {
      if (skipFile || !currentFile) {
        inHunk = false;
        continue;
      }
      inHunk = true;
      oldRemaining = hunkMatch[2] !== undefined ? Number(hunkMatch[2]) : 1;
      newRemaining = hunkMatch[4] !== undefined ? Number(hunkMatch[4]) : 1;
      currentLine = Number(hunkMatch[3]);
      continue;
    }

    if (!inHunk || skipFile || !currentFile) {
      continue;
    }

    if (rawLine.startsWith('+') && !rawLine.startsWith('+++ ')) {
      results.push({
        file: currentFile,
        line: currentLine,
        content: rawLine.slice(1),
      });
      currentLine += 1;
      if (newRemaining > 0) newRemaining -= 1;
    } else if (rawLine.startsWith(' ')) {
      currentLine += 1;
      if (oldRemaining > 0) oldRemaining -= 1;
      if (newRemaining > 0) newRemaining -= 1;
    } else if (rawLine.startsWith('-')) {
      if (oldRemaining > 0) oldRemaining -= 1;
    }
    // '\ No newline at end of file' leaves line numbers and counts unchanged.
  }

  return results;
}

/**
 * Runs `git diff` to obtain unified diff output with zero context lines (`-U0`).
 *
 * @param {{ unstaged?: boolean, cwd?: string }} [options]
 * @returns {string}
 */
export function getGitDiff({ unstaged = false, cwd = process.cwd() } = {}) {
  const args = [
    '-c',
    'core.quotepath=false',
    'diff',
    ...(unstaged ? [] : ['--cached']),
    '-U0',
    '--no-color',
  ];

  try {
    return execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      maxBuffer: 50 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    const stderr = err?.stderr ? String(err.stderr).trim() : '';
    const detail = stderr || err?.message || 'Unknown git error';
    throw new Error(`Failed to execute git diff: ${detail}`);
  }
}

/**
 * Retrieves and parses newly added lines from the current git diff.
 *
 * @param {{ unstaged?: boolean, cwd?: string }} [options]
 * @returns {Array<{ file: string, line: number, content: string }>}
 */
export function getAddedLines(options = {}) {
  const diffText = getGitDiff(options);
  return parseDiff(diffText);
}
