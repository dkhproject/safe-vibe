import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { parseDiff, isLockfile } from '../src/diffParser.js';
import { auditLines, hasBlockingIssues, shannonEntropy } from '../src/rules.js';
import {
  installHook,
  uninstallHook,
  HOOK_START_MARKER,
  HOOK_END_MARKER,
} from '../src/hookManager.js';
import { formatReport, shouldUseColor } from '../src/reporter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_PATH = path.resolve(__dirname, '../bin/cli.js');

function runCli(args, cwd) {
  return spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
}

function createTempGitRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-vibe-test-'));
  execFileSync('git', ['init'], { cwd: dir, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.name', 'Test User'], { cwd: dir, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: dir, stdio: 'ignore' });
  return dir;
}

describe('isLockfile', () => {
  it('detects common lockfiles and .lock extensions', () => {
    assert.equal(isLockfile('package-lock.json'), true);
    assert.equal(isLockfile('apps/web/pnpm-lock.yaml'), true);
    assert.equal(isLockfile('yarn.lock'), true);
    assert.equal(isLockfile('Cargo.lock'), true);
    assert.equal(isLockfile('go.sum'), true);
    assert.equal(isLockfile('custom.lock'), true);
    assert.equal(isLockfile('src/index.js'), false);
    assert.equal(isLockfile('package.json'), false);
  });
});

describe('parseDiff', () => {
  it('extracts only newly added lines with exact line numbers across hunks and files', () => {
    const diff = [
      'diff --git a/src/app.js b/src/app.js',
      'index 1111111..2222222 100644',
      '--- a/src/app.js',
      '+++ b/src/app.js',
      '@@ -10,2 +10,3 @@ function init() {',
      '-const oldA = 1;',
      '-const oldB = 2;',
      '+const newA = 10;',
      '+const newB = 20;',
      '+const newC = 30;',
      '@@ -25,0 +26,2 @@ function next() {',
      '+++counter;',
      '+  return counter;',
      'diff --git a/src/new.js b/src/new.js',
      'new file mode 100644',
      'index 0000000..3333333',
      '--- /dev/null',
      '+++ b/src/new.js',
      '@@ -0,0 +1,2 @@',
      '+export const x = 1;',
      '+export const y = 2;',
    ].join('\n');

    const added = parseDiff(diff);
    assert.deepEqual(added, [
      { file: 'src/app.js', line: 10, content: 'const newA = 10;' },
      { file: 'src/app.js', line: 11, content: 'const newB = 20;' },
      { file: 'src/app.js', line: 12, content: 'const newC = 30;' },
      { file: 'src/app.js', line: 26, content: '++counter;' },
      { file: 'src/app.js', line: 27, content: '  return counter;' },
      { file: 'src/new.js', line: 1, content: 'export const x = 1;' },
      { file: 'src/new.js', line: 2, content: 'export const y = 2;' },
    ]);
  });

  it('tracks line numbers accurately when context lines are present', () => {
    const diff = [
      'diff --git a/src/util.js b/src/util.js',
      '--- a/src/util.js',
      '+++ b/src/util.js',
      '@@ -4,4 +4,4 @@',
      ' const a = 1;',
      '-const b = 2;',
      '+const b = 3;',
      ' const c = 4;',
      '+const d = 5;',
    ].join('\n');

    const added = parseDiff(diff);
    assert.deepEqual(added, [
      { file: 'src/util.js', line: 5, content: 'const b = 3;' },
      { file: 'src/util.js', line: 7, content: 'const d = 5;' },
    ]);
  });

  it('ignores deleted files, binary files, and lockfiles', () => {
    const diff = [
      'diff --git a/src/removed.js b/src/removed.js',
      'deleted file mode 100644',
      'index 1111111..0000000',
      '--- a/src/removed.js',
      '+++ /dev/null',
      '@@ -1,2 +0,0 @@',
      '-eval("old");',
      '-const secret = "x";',
      'diff --git a/assets/logo.png b/assets/logo.png',
      'new file mode 100644',
      'index 0000000..4444444',
      'Binary files /dev/null and b/assets/logo.png differ',
      'diff --git a/package-lock.json b/package-lock.json',
      'index 1111111..2222222 100644',
      '--- a/package-lock.json',
      '+++ b/package-lock.json',
      '@@ -1,0 +2,1 @@',
      '+  "integrity": "sha512-abc"',
      'diff --git a/src/keep.js b/src/keep.js',
      '--- a/src/keep.js',
      '+++ b/src/keep.js',
      '@@ -1,1 +1,1 @@',
      '--- select comment',
      '+const ok = true;',
    ].join('\n');

    const added = parseDiff(diff);
    assert.deepEqual(added, [{ file: 'src/keep.js', line: 1, content: 'const ok = true;' }]);
  });
});

describe('auditLines - secrets', () => {
  it('detects AWS, GitHub, Anthropic, OpenAI, and private key literals', () => {
    const awsKey = 'AKIA' + 'IOSFODNN7EXAMPLE';
    const ghToken = 'ghp_' + '1234567890abcdef1234567890abcdef1234';
    const antKey = 'sk-ant-api03-' + 'AbCdEf1234567890_xyz';
    const oaiKey = 'sk-proj-' + 'AbCdEf1234567890_xyz';
    const privHeader = '-----BEGIN RSA ' + 'PRIVATE KEY-----';

    const findings = auditLines([
      { file: 'a.js', line: 1, content: `const aws = "${awsKey}";` },
      { file: 'a.js', line: 2, content: `const gh = "${ghToken}";` },
      { file: 'a.js', line: 3, content: `const ant = "${antKey}";` },
      { file: 'a.js', line: 4, content: `const oai = "${oaiKey}";` },
      { file: 'a.js', line: 5, content: `const pem = "${privHeader}";` },
    ]);

    assert.deepEqual(
      findings.map((f) => f.ruleId),
      [
        'secret-aws-access-key',
        'secret-github-token',
        'secret-anthropic-key',
        'secret-openai-key',
        'secret-private-key',
      ]
    );
    assert.equal(findings.every((f) => f.severity === 'critical'), true);
  });

  it('detects generic high-entropy credential assignments and skips placeholders', () => {
    const highEntropy = 'v8K!mP2$xQ9#zR4@wL7';
    assert.ok(shannonEntropy(highEntropy) >= 3.2);

    const findings = auditLines([
      { file: 'cfg.js', line: 1, content: `const api_key = "${highEntropy}";` },
      { file: 'cfg.json', line: 2, content: `  "client_secret": "${highEntropy}"` },
      // Should NOT trigger:
      { file: 'cfg.js', line: 3, content: 'const api_key = process.env.API_KEY;' },
      { file: 'cfg.js', line: 4, content: 'const api_key = "${process.env.API_KEY}";' },
      { file: 'cfg.js', line: 5, content: 'const secret = "your_secret_value_here";' },
      { file: 'cfg.js', line: 6, content: 'const password = "xxxxxxxxxxxx";' },
      { file: 'cfg.js', line: 7, content: 'const password = "short";' },
      { file: 'cfg.js', line: 8, content: `if (password === "${highEntropy}") {}` },
      { file: 'cfg.js', line: 9, content: `const passwordLabel = "${highEntropy}";` },
    ]);

    assert.equal(findings.length, 2);
    assert.equal(findings[0].ruleId, 'secret-generic-assignment');
    assert.equal(findings[1].ruleId, 'secret-generic-assignment');
  });
});

describe('auditLines - error handling', () => {
  it('detects single-line and multi-line empty catch and except blocks', () => {
    const findings = auditLines([
      { file: 'a.js', line: 1, content: 'try { doA(); } catch (e) {}' },
      { file: 'a.js', line: 2, content: 'try { doB(); } catch { /* ignored */ }' },
      { file: 'b.js', line: 10, content: '} catch (err) {' },
      { file: 'b.js', line: 11, content: '  // TODO nothing' },
      { file: 'b.js', line: 12, content: '}' },
      { file: 'c.js', line: 20, content: '} catch (err) {' },
      { file: 'c.js', line: 21, content: '  console.error(err);' },
      { file: 'c.js', line: 22, content: '}' },
      // Non-adjacent lines in same file must not be treated as a block:
      { file: 'd.js', line: 1, content: '} catch (err) {' },
      { file: 'd.js', line: 9, content: '}' },
      // Python except:
      { file: 'a.py', line: 1, content: 'except Exception: pass' },
      { file: 'a.py', line: 2, content: 'except ValueError: ...' },
      { file: 'b.py', line: 5, content: 'except KeyError:' },
      { file: 'b.py', line: 6, content: '    # swallow' },
      { file: 'b.py', line: 7, content: '    pass' },
      { file: 'c.py', line: 10, content: 'except RuntimeError as err:' },
      { file: 'c.py', line: 11, content: '    logger.exception(err)' },
    ]);

    assert.deepEqual(
      findings.map((f) => `${f.file}:${f.line}:${f.ruleId}`),
      [
        'a.js:1:silent-empty-catch',
        'a.js:2:silent-empty-catch',
        'b.js:10:silent-empty-catch',
        'a.py:1:silent-empty-except',
        'a.py:2:silent-empty-except',
        'b.py:5:silent-empty-except',
      ]
    );
  });
});

describe('auditLines - injection & dangerous execution', () => {
  it('flags eval, new Function, exec templates, dangerouslySetInnerHTML, and raw SQL', () => {
    const findings = auditLines([
      { file: 'a.js', line: 1, content: 'const res = eval(userCode);' },
      { file: 'a.js', line: 2, content: 'window.eval(userCode);' },
      { file: 'a.js', line: 3, content: 'const fn = new Function("a", body);' },
      { file: 'a.js', line: 4, content: 'child_process.exec(`rm -rf ${target}`);' },
      { file: 'a.js', line: 5, content: 'execSync(`ls ${dir}`);' },
      { file: 'a.jsx', line: 6, content: '<div dangerouslySetInnerHTML={{ __html: html }} />' },
      { file: 'db.js', line: 7, content: 'db.query(`SELECT * FROM users WHERE id = ${id}`);' },
      { file: 'db.js', line: 8, content: 'db.query(`UPDATE ${tbl} SET active = true`);' },
      { file: 'db.js', line: 9, content: 'db.query("DELETE FROM users WHERE id = " + req.id);' },
      // Safe alternatives:
      { file: 'ml.py', line: 10, content: 'model.eval()' },
      { file: 'a.js', line: 11, content: 'execSync("npm test");' },
      { file: 'db.js', line: 12, content: 'db.query(`SELECT * FROM users WHERE id = $1`, [id]);' },
      { file: 'db.js', line: 13, content: 'db.query("SELECT * FROM users " + "WHERE id = ?", [id]);' },
    ]);

    assert.deepEqual(
      findings.map((f) => `${f.file}:${f.line}:${f.ruleId}`),
      [
        'a.js:1:dangerous-eval',
        'a.js:2:dangerous-eval',
        'a.js:3:dangerous-new-function',
        'a.js:4:dangerous-exec-template',
        'a.js:5:dangerous-exec-template',
        'a.jsx:6:dangerous-inner-html',
        'db.js:7:dangerous-raw-sql',
        'db.js:8:dangerous-raw-sql',
        'db.js:9:dangerous-raw-sql',
      ]
    );
  });
});

describe('auditLines - debris & inline ignores', () => {
  it('flags TODO: implement, FIXME, and sensitive console logs', () => {
    const findings = auditLines([
      { file: 'a.js', line: 1, content: '// TODO: implement rate limiting' },
      { file: 'a.py', line: 2, content: '# FIXME: handle retry' },
      { file: 'a.js', line: 3, content: 'console.log("Auth token:", authToken);' },
      { file: 'a.js', line: 4, content: 'console.error("Failed password:", userPassword);' },
      { file: 'a.js', line: 5, content: 'console.log("User logged in:", userId);' },
    ]);

    assert.deepEqual(
      findings.map((f) => ({ line: f.line, ruleId: f.ruleId, severity: f.severity })),
      [
        { line: 1, ruleId: 'debris-placeholder', severity: 'medium' },
        { line: 2, ruleId: 'debris-placeholder', severity: 'medium' },
        { line: 3, ruleId: 'debris-sensitive-log', severity: 'high' },
        { line: 4, ruleId: 'debris-sensitive-log', severity: 'high' },
      ]
    );
    assert.equal(hasBlockingIssues([findings[0]]), false);
    assert.equal(hasBlockingIssues([findings[0]], { strict: true }), true);
    assert.equal(hasBlockingIssues([findings[2]]), true);
  });

  it('respects // safe-vibe-ignore and # safe-vibe-ignore', () => {
    const awsKey = 'AKIA' + 'IOSFODNN7EXAMPLE';
    const findings = auditLines([
      { file: 'a.js', line: 1, content: `const k = "${awsKey}"; // safe-vibe-ignore` },
      { file: 'a.js', line: 2, content: 'eval(trustedCode); // safe-vibe-ignore' },
      { file: 'a.py', line: 3, content: 'except Exception: pass # safe-vibe-ignore' },
      { file: 'b.js', line: 10, content: '} catch (e) {' },
      { file: 'b.js', line: 11, content: '  // safe-vibe-ignore' },
      { file: 'b.js', line: 12, content: '}' },
      { file: 'c.js', line: 20, content: '} catch (e) { // safe-vibe-ignore' },
      { file: 'c.js', line: 21, content: '}' },
    ]);

    assert.deepEqual(findings, []);
  });
});

describe('hookManager', () => {
  it('installs and uninstalls pre-commit hook cleanly in a fresh repo', () => {
    const repoDir = createTempGitRepo();
    try {
      const installRes = installHook(repoDir);
      assert.equal(installRes.status, 'installed');
      assert.equal(fs.existsSync(installRes.hookPath), true);

      const mode = fs.statSync(installRes.hookPath).mode & 0o777;
      assert.equal(mode, 0o755);

      const hookBody = fs.readFileSync(installRes.hookPath, 'utf8');
      assert.ok(hookBody.startsWith('#!/bin/sh'));
      assert.ok(hookBody.includes(HOOK_START_MARKER));
      assert.ok(hookBody.includes(HOOK_END_MARKER));
      assert.ok(hookBody.includes('npx --no-install safe-vibe'));

      const secondInstall = installHook(repoDir);
      assert.equal(secondInstall.status, 'already_installed');

      const uninstallRes = uninstallHook(repoDir);
      assert.equal(uninstallRes.status, 'removed_file');
      assert.equal(fs.existsSync(installRes.hookPath), false);

      const missingUninstall = uninstallHook(repoDir);
      assert.equal(missingUninstall.status, 'not_found');
    } finally {
      fs.rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('appends to and cleanly uninstalls from an existing user pre-commit hook', () => {
    const repoDir = createTempGitRepo();
    try {
      const hookPath = path.join(repoDir, '.git', 'hooks', 'pre-commit');
      fs.mkdirSync(path.dirname(hookPath), { recursive: true });
      fs.writeFileSync(hookPath, '#!/bin/sh\necho "running user tests"\n', { mode: 0o644 });

      const notInstalledRes = uninstallHook(repoDir);
      assert.equal(notInstalledRes.status, 'not_installed');

      const appendRes = installHook(repoDir);
      assert.equal(appendRes.status, 'appended');
      assert.equal(fs.statSync(hookPath).mode & 0o777, 0o755);

      const combined = fs.readFileSync(hookPath, 'utf8');
      assert.ok(combined.includes('echo "running user tests"'));
      assert.ok(combined.includes(HOOK_START_MARKER));

      const uninstallRes = uninstallHook(repoDir);
      assert.equal(uninstallRes.status, 'removed_block');
      assert.equal(fs.existsSync(hookPath), true);

      const after = fs.readFileSync(hookPath, 'utf8');
      assert.equal(after, '#!/bin/sh\necho "running user tests"\n');
    } finally {
      fs.rmSync(repoDir, { recursive: true, force: true });
    }
  });
});

describe('reporter', () => {
  it('respects NO_COLOR, FORCE_COLOR, and TTY flags', () => {
    assert.equal(shouldUseColor({ env: { NO_COLOR: '1', FORCE_COLOR: '1' }, isTTY: true }), false);
    assert.equal(shouldUseColor({ env: { FORCE_COLOR: '1' }, isTTY: false }), true);
    assert.equal(shouldUseColor({ env: { FORCE_COLOR: '0' }, isTTY: false }), false);
    assert.equal(shouldUseColor({ env: {}, isTTY: true }), true);
    assert.equal(shouldUseColor({ env: {}, isTTY: false }), false);
  });

  it('formats plain and ANSI-colored reports with badges, tips, and summaries', () => {
    const cleanPlain = formatReport([], { scannedLineCount: 4, color: false });
    assert.match(cleanPlain, /✔ Safe to commit — no vibe-coding traps found/);
    assert.doesNotMatch(cleanPlain, /\x1b\[/);

    const findings = auditLines([
      { file: 'app.js', line: 3, content: 'eval(x);' },
      { file: 'app.js', line: 8, content: 'try { a(); } catch (e) {}' },
      { file: 'app.js', line: 12, content: '// TODO: implement auth' },
    ]);

    const plainBlocked = formatReport(findings, { scannedLineCount: 3, color: false });
    assert.match(plainBlocked, /\[CRITICAL\] app\.js:3 \(dangerous-eval\)/);
    assert.match(plainBlocked, /\[HIGH\] app\.js:8 \(silent-empty-catch\)/);
    assert.match(plainBlocked, /\[MEDIUM\] app\.js:12 \(debris-placeholder\)/);
    assert.match(plainBlocked, /Tip: Replace eval\(\)/);
    assert.match(plainBlocked, /✖ Commit blocked by safe-vibe \(1 critical, 1 high, 1 medium\)/);
    assert.doesNotMatch(plainBlocked, /\x1b\[/);

    const coloredBlocked = formatReport(findings, { scannedLineCount: 3, color: true });
    assert.match(coloredBlocked, /\x1b\[1m\x1b\[31m\[CRITICAL\]\x1b\[0m/);
    assert.match(coloredBlocked, /\x1b\[1m\x1b\[33m\[HIGH\]\x1b\[0m/);
    assert.match(coloredBlocked, /\x1b\[36m\[MEDIUM\]\x1b\[0m/);

    const mediumOnly = [findings[2]];
    const mediumPass = formatReport(mediumOnly, { scannedLineCount: 1, strict: false, color: false });
    assert.match(mediumPass, /✔ Safe to commit — no blocking traps found \(1 medium warning\)/);

    const mediumStrict = formatReport(mediumOnly, { scannedLineCount: 1, strict: true, color: false });
    assert.match(mediumStrict, /✖ Commit blocked by safe-vibe \(1 medium\)/);
  });
});

describe('CLI integration', () => {
  it('prints help and version with --help and --version / -v', () => {
    const helpRes = runCli(['--help'], process.cwd());
    assert.equal(helpRes.status, 0);
    assert.match(helpRes.stdout, /Usage:\s+safe-vibe/);

    const verRes = runCli(['--version'], process.cwd());
    assert.equal(verRes.status, 0);
    assert.match(verRes.stdout.trim(), /^safe-vibe v\d+\.\d+\.\d+$/);

    const shortVerRes = runCli(['-v'], process.cwd());
    assert.equal(shortVerRes.status, 0);
    assert.equal(shortVerRes.stdout, verRes.stdout);
  });

  it('supports install/uninstall subcommands and --strict mode', () => {
    const repoDir = createTempGitRepo();
    try {
      const installRes = runCli(['install'], repoDir);
      assert.equal(installRes.status, 0);
      assert.match(installRes.stdout, /Installed safe-vibe pre-commit hook/);

      const hookPath = path.join(repoDir, '.git', 'hooks', 'pre-commit');
      assert.equal(fs.existsSync(hookPath), true);

      const uninstallRes = runCli(['uninstall'], repoDir);
      assert.equal(uninstallRes.status, 0);
      assert.match(uninstallRes.stdout, /Removed safe-vibe pre-commit hook/);
      assert.equal(fs.existsSync(hookPath), false);

      const badCmdRes = runCli(['unknown-cmd'], repoDir);
      assert.equal(badCmdRes.status, 1);
      assert.match(badCmdRes.stderr, /Unknown command/);

      // Stage medium-only finding: passes by default, blocked under --strict
      const filePath = path.join(repoDir, 'todo.js');
      fs.writeFileSync(filePath, '// TODO: implement auth\n');
      execFileSync('git', ['add', 'todo.js'], { cwd: repoDir });

      const defaultRes = runCli([], repoDir);
      assert.equal(defaultRes.status, 0);
      assert.match(defaultRes.stdout, /Safe to commit/);

      const strictRes = runCli(['--strict'], repoDir);
      assert.equal(strictRes.status, 1);
      assert.match(strictRes.stdout, /Commit blocked by safe-vibe \(1 medium\)/);
    } finally {
      fs.rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('blocks critical/high staged changes, supports --unstaged, and passes on clean/medium/ignored diffs', () => {
    const repoDir = createTempGitRepo();
    try {
      const filePath = path.join(repoDir, 'index.js');

      // 1. Clean staged file -> exit 0
      fs.writeFileSync(filePath, 'export const safe = 42;\n');
      execFileSync('git', ['add', 'index.js'], { cwd: repoDir });
      let res = runCli([], repoDir);
      assert.equal(res.status, 0);

      // 2. Staged critical issue -> exit 1
      fs.writeFileSync(filePath, 'export const bad = eval(input);\n');
      execFileSync('git', ['add', 'index.js'], { cwd: repoDir });
      res = runCli(['--json'], repoDir);
      assert.equal(res.status, 1);
      const parsed = JSON.parse(res.stdout);
      assert.equal(parsed.blocking, true);
      assert.equal(parsed.findings[0].ruleId, 'dangerous-eval');

      // 3. Commit safe code, then introduce unstaged high issue
      fs.writeFileSync(filePath, 'export const safe = 42;\n');
      execFileSync('git', ['add', 'index.js'], { cwd: repoDir });
      execFileSync('git', ['commit', '-m', 'init'], { cwd: repoDir, stdio: 'ignore' });

      fs.writeFileSync(filePath, 'export const safe = 42;\ntry { x(); } catch (e) {}\n');
      // Staged diff is empty -> exit 0
      res = runCli([], repoDir);
      assert.equal(res.status, 0);
      // Unstaged diff catches empty catch -> exit 1
      res = runCli(['--unstaged'], repoDir);
      assert.equal(res.status, 1);
      assert.match(res.stdout, /silent-empty-catch/);

      // 4. Medium-only or inline-ignored staged changes -> exit 0
      fs.writeFileSync(
        filePath,
        [
          'export const safe = 42;',
          '// TODO: implement validation',
          'eval(trusted); // safe-vibe-ignore',
          '',
        ].join('\n')
      );
      execFileSync('git', ['add', 'index.js'], { cwd: repoDir });
      res = runCli([], repoDir);
      assert.equal(res.status, 0);
      assert.match(res.stdout, /debris-placeholder/);
      assert.doesNotMatch(res.stdout, /dangerous-eval/);
    } finally {
      fs.rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('exits 1 with an error when run outside a git repository', () => {
    const nonRepoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-vibe-nogit-'));
    try {
      const res = runCli([], nonRepoDir);
      assert.equal(res.status, 1);
      assert.match(res.stderr, /safe-vibe error:/);
    } finally {
      fs.rmSync(nonRepoDir, { recursive: true, force: true });
    }
  });
});
