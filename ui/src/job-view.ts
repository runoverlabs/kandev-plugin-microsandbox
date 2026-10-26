import type { Component, PluginHostApi } from "@kandev/plugin-sdk";
import { invoke, toActionError, type ActionError } from "./api";
import { kit } from "./common";
import { stepTone, type SetupJob } from "./model";

// A setup job is followed this often; one runs for minutes.
const POLL_MS = 1500;

export interface JobViewProps {
  job: SetupJob;
  title: string;
  onFinished(): void;
  onAgain?: () => void;
  onClose(): void;
}

/** A setup or upgrade job's steps, followed until it finishes. */
export function createJobView(host: PluginHostApi): Component<JobViewProps> {
  const k = kit(host);
  return function JobView(props: JobViewProps) {
    const [job, setJob] = host.React.useState<SetupJob>(props.job);
    const [error, setError] = host.React.useState<ActionError | null>(null);
    // A failed poll schedules the next one, so a plugin restart or a slow
    // answer does not leave a running job looking stuck.
    const [failures, setFailures] = host.React.useState(0);
    host.React.useEffect(() => {
      if (job.state !== "running") return;
      const controller = new AbortController();
      const timer = window.setTimeout(() => {
        invoke<SetupJob>(host, "hosts.setup.status", { id: job.id }, controller.signal)
          .then((next) => {
            setError(null);
            setJob(next);
            if (next.state !== "running") props.onFinished();
          })
          .catch((cause: unknown) => {
            if (controller.signal.aborted) return;
            const failure = toActionError(cause);
            setError(failure);
            if (failure.status >= 400 && failure.status < 500) {
              // The plugin no longer knows the job, as after a restart: polling
              // cannot bring it back, so it ends here and can be run again.
              setJob({ ...job, state: "failed" });
              props.onFinished();
            } else {
              setFailures((n) => n + 1);
            }
          });
      }, POLL_MS);
      return () => {
        window.clearTimeout(timer);
        controller.abort();
      };
    }, [job, failures]);
    return k.card(
      props.title,
      job.state === "running" ? "Running. This can take a few minutes." : job.state === "done" ? "Done." : "Stopped. Fix what the failed step says, then run it again: every step is safe to repeat.",
      k.error(error),
      k.h(
        "ol",
        { className: "msb-checklist" },
        ...job.steps.map((step) =>
          k.h(
            "li",
            { key: step.key, className: "msb-checklist__item", "data-testid": `step-${step.key}` },
            k.h("div", { className: "msb-row" }, k.badge(stepTone(step.state), step.state), k.h("span", null, step.title)),
            step.detail ? k.h("p", { className: "msb-muted" }, step.detail) : null,
            step.commands?.length ? k.code(step.commands.join("\n")) : null,
            step.output ? k.code(step.output) : null,
          ),
        ),
      ),
      job.manual?.length ? k.h("div", null, k.h("strong", null, "Still to do:"), k.h("ul", null, ...job.manual.map((m, i) => k.h("li", { key: i }, m)))) : null,
      k.h(
        "div",
        { className: "msb-row" },
        job.state !== "running" && props.onAgain ? k.button("Run it again", props.onAgain) : null,
        k.button("Close", props.onClose, { variant: "ghost" }),
      ),
    );
  };
}
