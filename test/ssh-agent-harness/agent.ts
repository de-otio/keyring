import { type ChildProcess, spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

/**
 * Spawn a real `ssh-agent` subprocess, import a provided test key, and expose
 * the socket path so `src/ssh/agent.ts` can dial it over Unix-domain sockets.
 *
 * Phase A scaffolding. Phase C integration tests exercise the actual
 * `ssh-agent.ts` IPC against this harness. Windows uses named-pipe IPC which
 * requires a different spawn strategy — out of scope here; Windows ssh-agent
 * tests run against the built-in OpenSSH agent on the runner (Windows 10+).
 */
export interface SshAgentHarness {
  socketPath: string;
  pid: number;
  importKey(privateKeyPem: string): Promise<void>;
  dispose(): Promise<void>;
}

export async function startSshAgent(): Promise<SshAgentHarness> {
  if (process.platform === 'win32') {
    throw new Error(
      'startSshAgent harness does not support Windows; use the built-in OpenSSH agent',
    );
  }

  const dir = await mkdtemp(path.join(tmpdir(), 'keyring-ssh-agent-'));
  const socketPath = path.join(dir, 'agent.sock');

  // `ssh-agent -a <socket>` binds to the given socket and prints shell
  // variables to stdout (we ignore stdout and use -D to stay foreground).
  const child: ChildProcess = spawn('ssh-agent', ['-D', '-a', socketPath], {
    env: { ...process.env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  await waitForSocket(socketPath, 2000);

  const importKey = async (privateKeyPem: string): Promise<void> => {
    const keyFile = path.join(dir, 'test-key');
    await writeFile(keyFile, privateKeyPem, { mode: 0o600 });
    await new Promise<void>((resolve, reject) => {
      const add = spawn('ssh-add', [keyFile], {
        env: { ...process.env, SSH_AUTH_SOCK: socketPath },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      add.on('exit', (code) =>
        code === 0 ? resolve() : reject(new Error(`ssh-add exited ${code}`)),
      );
      add.on('error', reject);
    });
  };

  const dispose = async (): Promise<void> => {
    if (child.pid && !child.killed) {
      child.kill('SIGTERM');
      await new Promise<void>((resolve) => child.once('exit', () => resolve()));
    }
    await rm(dir, { recursive: true, force: true });
  };

  return { socketPath, pid: child.pid ?? -1, importKey, dispose };
}

async function waitForSocket(socketPath: string, timeoutMs: number): Promise<void> {
  const { stat } = await import('node:fs/promises');
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const s = await stat(socketPath);
      if (s.isSocket()) return;
    } catch {
      // not yet
    }
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`ssh-agent socket did not appear at ${socketPath} within ${timeoutMs}ms`);
}
