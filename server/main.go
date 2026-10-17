// Command kandev-plugin-microsandbox is the backend half of this Kandev
// plugin. Kandev spawns it as a gRPC subprocess; pluginsdk.Serve owns the
// transport.
package main

import (
	"kandev-plugin-microsandbox/internal/plugin"

	"github.com/kandev/kandev/pkg/pluginsdk"
)

func main() {
	runtime := plugin.NewRuntime()
	defer runtime.Close()
	pluginsdk.Serve(runtime)
}
