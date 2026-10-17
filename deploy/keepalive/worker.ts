export interface Env {
  INSTABOX_API_KEY: string;
  INSTABOX_SANDBOX_ID: string;
}

const API_ROOT = "https://api.instabox.sh/v1";
const API_TIMEOUT_MS = 10_000;
const MAX_READ_ATTEMPTS = 2;
const MAX_OPERATION_WAIT_MS = 75_000;

type Machine = { id: string; state: string };
type Operation = { id: string; state: "queued" | "running" | "succeeded" | "failed" };
type ExecResult = { exitCode: number; timedOut: boolean };

class KeepaliveError extends Error {}

function validateEnv(env: Env): void {
  if (!env.INSTABOX_API_KEY || !env.INSTABOX_SANDBOX_ID) {
    throw new KeepaliveError("required_secret_missing");
  }
}

async function request<T>(
  env: Env,
  path: string,
  init: RequestInit = {},
  retryRead = false,
): Promise<T> {
  const attempts = retryRead ? MAX_READ_ATTEMPTS : 1;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    let response: Response;
    try {
      response = await fetch(`${API_ROOT}${path}`, {
        ...init,
        headers: {
          Authorization: `Bearer ${env.INSTABOX_API_KEY}`,
          ...(init.body ? { "Content-Type": "application/json" } : {}),
          ...init.headers,
        },
        signal: AbortSignal.timeout(path.startsWith("/operations/") ? 30_000 : API_TIMEOUT_MS),
      });
    } catch {
      if (attempt < attempts) continue;
      throw new KeepaliveError("instabox_request_failed");
    }

    if (response.ok) {
      if (response.status === 204) return undefined as T;
      try {
        return (await response.json()) as T;
      } catch {
        throw new KeepaliveError("instabox_invalid_response");
      }
    }

    if (retryRead && attempt < attempts && (response.status === 429 || response.status >= 500)) continue;
    throw new KeepaliveError(`instabox_http_${response.status}`);
  }
  throw new KeepaliveError("instabox_request_failed");
}

async function waitForOperation(env: Env, operationId: string): Promise<void> {
  const deadline = Date.now() + MAX_OPERATION_WAIT_MS;
  while (Date.now() < deadline) {
    const remainingSeconds = Math.max(1, Math.ceil((deadline - Date.now()) / 1000));
    const wait = `${Math.min(25, remainingSeconds)}s`;
    const operation = await request<Operation>(
      env,
      `/operations/${encodeURIComponent(operationId)}?wait=${wait}`,
      {},
      true,
    );
    if (operation.state === "succeeded") return;
    if (operation.state === "failed") throw new KeepaliveError("instabox_operation_failed");
  }
  throw new KeepaliveError("instabox_operation_timeout");
}

async function changeState(env: Env, action: "resume" | "start"): Promise<void> {
  const operation = await request<Operation>(
    env,
    `/machines/${encodeURIComponent(env.INSTABOX_SANDBOX_ID)}/${action}`,
    { method: "POST", headers: { "Idempotency-Key": crypto.randomUUID() } },
  );
  if (!operation?.id) throw new KeepaliveError("instabox_operation_missing_id");
  await waitForOperation(env, operation.id);
}

async function runKeepalive(env: Env): Promise<void> {
  validateEnv(env);
  const machinePath = `/machines/${encodeURIComponent(env.INSTABOX_SANDBOX_ID)}`;
  let machine = await request<Machine>(env, machinePath, {}, true);

  if (machine.state === "suspended") {
    await changeState(env, "resume");
    machine = await request<Machine>(env, machinePath, {}, true);
  } else if (machine.state === "stopped") {
    await changeState(env, "start");
    machine = await request<Machine>(env, machinePath, {}, true);
  }

  if (machine.state !== "running") {
    throw new KeepaliveError("unexpected_machine_state");
  }

  const result = await request<ExecResult>(
    env,
    `${machinePath}/exec`,
    { method: "POST", body: JSON.stringify({ cmd: "true", timeoutSeconds: 5 }) },
  );
  if (result.exitCode !== 0 || result.timedOut) {
    throw new KeepaliveError("keepalive_command_failed");
  }
}

export default {
  async fetch(request: Request): Promise<Response> {
    if (new URL(request.url).pathname === "/health" && request.method === "GET") {
      return new Response("ok", { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
    }
    return new Response("not found", { status: 404 });
  },

  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    try {
      await runKeepalive(env);
      console.log("[keepalive] completed");
    } catch (error) {
      const code = error instanceof KeepaliveError ? error.message : "unexpected_error";
      console.error(`[keepalive] failed: ${code}`);
      throw error instanceof KeepaliveError ? error : new KeepaliveError(code);
    }
  },
};
