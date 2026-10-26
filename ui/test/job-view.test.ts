import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createJobView, type JobViewProps } from "../src/job-view";
import type { SetupJob } from "../src/model";

// A minimal hooks runtime: state persists across renders, a setter
// re-renders, and an effect runs after a render when its deps change, so the
// job view's polling runs as it would in React.
function mount(answers: Array<SetupJob | { status: number }>, props: Omit<JobViewProps, "job" | "title" | "onClose">, job: SetupJob) {
  const slots: unknown[] = [];
  const effects: Array<{ deps: unknown[] | undefined; cleanup: (() => void) | undefined }> = [];
  const calls: string[] = [];
  let slot = 0;
  let effect = 0;
  let pending: Array<() => void> = [];
  const host: any = {
    jsx: () => null,
    ui: new Proxy({}, { get: (_, name) => String(name) }),
    React: {
      useState: (initial: unknown) => {
        const i = slot++;
        if (!(i in slots)) slots[i] = initial;
        return [slots[i], (next: unknown) => ((slots[i] = typeof next === "function" ? next(slots[i]) : next), render())];
      },
      useEffect: (run: () => (() => void) | void, deps?: unknown[]) => {
        const i = effect++;
        const prev = effects[i];
        if (prev && deps && prev.deps && deps.every((d, j) => Object.is(d, prev.deps![j]))) return;
        pending.push(() => {
          prev?.cleanup?.();
          effects[i] = { deps, cleanup: run() ?? undefined };
        });
      },
    },
    context: { getActiveWorkspaceId: () => "ws", getWorkspaceIds: () => ["ws"] },
    api: {
      invokeAction: (key: string) => {
        calls.push(key);
        const answer = answers.shift();
        if (!answer) return new Promise(() => undefined);
        return "status" in answer ? Promise.reject(answer) : Promise.resolve(answer);
      },
    },
  };
  const View = createJobView(host);
  const full: JobViewProps = { ...props, job, title: "Set up", onClose: () => undefined };
  function render() {
    slot = effect = 0;
    View(full);
    const run = pending;
    pending = [];
    run.forEach((f) => f());
  }
  render();
  return { calls, error: () => slots[1] };
}

const running: SetupJob = { id: "j1", name: "sbx-01", state: "running", steps: [] };
const done: SetupJob = { ...running, state: "done" };

describe("job view", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.stubGlobal("window", globalThis);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("keeps following a job through a failed poll", async () => {
    const onFinished = vi.fn();
    const view = mount([{ status: 503 }, { ...running }, done], { onFinished }, running);
    await vi.advanceTimersByTimeAsync(1500);
    expect(view.error()).not.toBeNull();
    await vi.advanceTimersByTimeAsync(3000);
    expect(view.calls).toHaveLength(3);
    expect(view.error()).toBeNull();
    expect(onFinished).toHaveBeenCalledOnce();
  });

  it("stops following a job the plugin no longer knows", async () => {
    const view = mount([{ status: 404 }], { onFinished: vi.fn() }, running);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(view.calls).toHaveLength(1);
    expect(view.error()).not.toBeNull();
  });
});
