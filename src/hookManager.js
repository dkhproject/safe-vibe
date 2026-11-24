import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

export const HOOK_START_MARKER = '# --- safe-vibe start ---';
export const HOOK_END_MARKER = '# --- safe-vibe end ---';

const HOOK_BLOCK = [
  HOOK_START_MARKER,
  'if command -v safe-vibe >/dev/null 2>&1; then',
  '  safe-vibe || exit 1',
  'else',
  '  npx --no-install safe-vibe || exit 1',
  'fi',
  HOOK_END_MARKER,
].join('\n');

/**
 * Resolves the `.git/hooks` directory for the repository at `cwd`.
 * @param {string} [cwd]
 * @returns {string}
 */
export function resolveHooksDir(cwd = process.cwd()) {
  let gitDir;
  try {
    gitDir = execFileSync('git', ['rev-parse', '--git-dir'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  } catch (err) {
    const stderr = err?.stderr ? String(err.stderr).trim() : '';
    throw new Error(stderr || 'Not inside a git repository');
  }

  return path.resolve(cwd, gitDir, 'hooks');
}

/**
 * Installs the `safe-vibe` pre-commit hook into `.git/hooks/pre-commit`.
 * Preserves existing hooks by appending a marked block.
 *
 * @param {string} [cwd]
 * @returns {{ status: 'installed' | 'appended' | 'already_installed', hookPath: string, message: string }}
 */
export function installHook(cwd = process.cwd()) {
  const hooksDir = resolveHooksDir(cwd);
  fs.mkdirSync(hooksDir, { recursive: true });
  const hookPath = path.join(hooksDir, 'pre-commit');

  if (!fs.existsSync(hookPath)) {
    fs.writeFileSync(hookPath, `#!/bin/sh\n\n${HOOK_BLOCK}\n`, { mode: 0o755 });
    fs.chmodSync(hookPath, 0o755);
    return {
      status: 'installed',
      hookPath,
      message: `Installed safe-vibe pre-commit hook at ${hookPath}`,
    };
  }

  const existing = fs.readFileSync(hookPath, 'utf8');
  if (existing.includes(HOOK_START_MARKER) || /\bsafe-vibe\b/.test(existing)) {
    return {
      status: 'already_installed',
      hookPath,
      message: `safe-vibe pre-commit hook is already active at ${hookPath}`,
    };
  }

  const separator =
    existing.length === 0
      ? ''
      : existing.endsWith('\n\n')
        ? ''
        : existing.endsWith('\n')
          ? '\n'
          : '\n\n';
  const nextContent = `${existing}${separator}${HOOK_BLOCK}\n`;
  fs.writeFileSync(hookPath, nextContent, 'utf8');
  fs.chmodSync(hookPath, 0o755);

  return {
    status: 'appended',
    hookPath,
    message: `Appended safe-vibe check to existing pre-commit hook at ${hookPath}`,
  };
}

/**
 * Removes the `safe-vibe` block from `.git/hooks/pre-commit`, or deletes the
 * file if nothing else remains.
 *
 * @param {string} [cwd]
 * @returns {{ status: 'removed_file' | 'removed_block' | 'not_found' | 'not_installed', hookPath: string, message: string }}
 */
export function uninstallHook(cwd = process.cwd()) {
  const hooksDir = resolveHooksDir(cwd);
  const hookPath = path.join(hooksDir, 'pre-commit');

  if (!fs.existsSync(hookPath)) {
    return {
      status: 'not_found',
      hookPath,
      message: `No pre-commit hook found at ${hookPath}`,
    };
  }

  const existing = fs.readFileSync(hookPath, 'utf8');
  const startIdx = existing.indexOf(HOOK_START_MARKER);
  const endIdx = existing.indexOf(HOOK_END_MARKER);

  if (startIdx === -1 || endIdx === -1 || endIdx < startIdx) {
    return {
      status: 'not_installed',
      hookPath,
      message: `No safe-vibe hook block found in ${hookPath}`,
    };
  }

  const before = existing.slice(0, startIdx).replace(/[ \t]*\r?\n*$/, '');
  const after = existing.slice(endIdx + HOOK_END_MARKER.length).replace(/^\r?\n*/, '');

  let remaining;
  if (before && after) {
    remaining = `${before}\n\n${after}`;
  } else {
    remaining = `${before}${after}`;
  }

  const cleaned = remaining.trim() ? `${remaining.replace(/\r?\n*$/, '')}\n` : '';
  if (!cleaned || /^#!\/[^\n]*\s*$/.test(cleaned)) {
    fs.unlinkSync(hookPath);
    return {
      status: 'removed_file',
      hookPath,
      message: `Removed safe-vibe pre-commit hook (${hookPath})`,
    };
  }

  fs.writeFileSync(hookPath, cleaned, 'utf8');
  return {
    status: 'removed_block',
    hookPath,
    message: `Removed safe-vibe block from ${hookPath} while preserving existing hooks`,
  };
}
