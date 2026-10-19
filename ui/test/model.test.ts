import { describe, expect, it } from "vitest";
import { formatMiB, hostBadge, olderVersion, hostDetail, parseDestination, readinessTone, splitList, stepTone, type HostView } from "../src/model";

const base: HostView = {
  name: "sbx-01", ssh: "msb@sbx-01.example.com", host_key: "ssh-ed25519 AAAA", base_url: "https://sbx-01.example.com",
  labels: ["default"], fingerprint: "SHA256:abc",
};

describe("host badge", () => {
  it("says what the last check found", () => {
    expect(hostBadge(base)).toEqual({ tone: "muted", label: "not checked" });
    expect(hostBadge({ ...base, status: { ok: true, checked_at: "x" } })).toEqual({ tone: "ok", label: "ready" });
    expect(hostBadge({ ...base, status: { ok: false, problem: "egress_refused", checked_at: "x" } })).toEqual({ tone: "bad", label: "egress refused" });
    expect(hostBadge({ ...base, draining: true, status: { ok: true, checked_at: "x" } }).label).toBe("draining");
  });
});

describe("host detail", () => {
  it("lists registration only before a check", () => {
    expect(hostDetail(base).map(([label]) => label)).toEqual(["SSH", "Base URL", "Labels", "Host key"]);
  });

  it("shows versions, machine facts and capacity once checked", () => {
    const rows = Object.fromEntries(
      hostDetail({
        ...base,
        status: {
          ok: true, checked_at: "2026-10-19T12:00:00Z",
          health: {
            msbctl_version: "0.5.1", msb_version: "0.7.7", platform: "linux-amd64", kvm: true,
            capacity: { max_sandboxes: 12, sandboxes: 3, max_cpus: 32, cpus: 8, max_memory_mib: 98304, memory_mib: 16384 },
            serve: { ok: true, mode: "proxy", listen: "10.0.1.23" },
            egress: { allow_extra: [] },
            host: { os: "Debian GNU/Linux 13 (trixie)", kernel: "6.12.48", cpus: 16, load_1m: 0.42, memory_total_mib: 65536, memory_available_mib: 51200, disk_total_gib: 900, disk_free_gib: 512, uptime_seconds: 90061 },
          },
        },
      }),
    );
    expect(rows.msbctl).toBe("0.5.1");
    expect(rows.OS).toBe("Debian GNU/Linux 13 (trixie)");
    expect(rows.CPUs).toBe("16, load 0.42");
    expect(rows.Memory).toBe("50 GiB free of 64 GiB");
    expect(rows.Disk).toBe("512 GiB free of 900 GiB");
    expect(rows.Uptime).toBe("1 d 1 h");
    expect(rows["Kandev sandboxes"]).toBe("3 of 12, 8 of 32 CPUs, 16 GiB of 96 GiB");
    expect(rows["Data path"]).toBe("proxy on 10.0.1.23, up");
    expect(rows.allow_extra).toBe("[] (nothing extra)");
    expect(rows["Last checked"]).toBe("2026-10-19T12:00:00Z");
  });
});

describe("helpers", () => {
  it("formats memory", () => {
    expect(formatMiB(512)).toBe("512 MiB");
    expect(formatMiB(1536)).toBe("1.5 GiB");
    expect(formatMiB(undefined)).toBe("");
  });

  it("splits lists typed with commas or newlines", () => {
    expect(splitList(" default, big-mem\n,gpu ,")).toEqual(["default", "big-mem", "gpu"]);
  });

  it("parses SSH destinations as the plugin does", () => {
    expect(parseDestination("ubuntu@203.0.113.10")).toEqual({ user: "ubuntu", host: "203.0.113.10", port: 22 });
    expect(parseDestination("msb@sbx-01:2222")).toEqual({ user: "msb", host: "sbx-01", port: 2222 });
    expect(parseDestination("root@[fd00::5]:22")).toEqual({ user: "root", host: "fd00::5", port: 22 });
    expect(parseDestination("nouser")).toBeNull();
    expect(parseDestination("u@host:99999")).toBeNull();
  });

  it("compares releases numerically", () => {
    expect(olderVersion("0.5.1", "0.6.0")).toBe(true);
    expect(olderVersion("0.6.0", "0.6.0")).toBe(false);
    expect(olderVersion("0.10.0", "0.9.9")).toBe(false);
    expect(olderVersion("", "0.6.0")).toBe(false);
  });

  it("maps states to tones", () => {
    expect(readinessTone("ok")).toBe("ok");
    expect(readinessTone("unknown")).toBe("warn");
    expect(readinessTone("untrusted")).toBe("bad");
    expect(stepTone("changed")).toBe("ok");
    expect(stepTone("manual")).toBe("warn");
    expect(stepTone("skipped")).toBe("muted");
  });
});
