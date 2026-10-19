// The window entry point Kandev exposes to a plugin bundle. The SDK types the
// registry and host; only the global is declared here.
import type { PluginHostApi, PluginRegistry } from "@kandev/plugin-sdk";

declare global {
  interface Window {
    registerKandevPlugin(
      id: string,
      lifecycle: {
        initialize(registry: PluginRegistry, host: PluginHostApi): void;
        destroy?(): void;
      },
    ): void;
  }
}

export {};
