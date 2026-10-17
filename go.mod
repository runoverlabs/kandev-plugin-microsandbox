module kandev-plugin-microsandbox

go 1.26.0

require (
	github.com/kandev/kandev v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.58.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-plugin v1.8.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// The Kandev SDK (pkg/pluginsdk) is not a published module yet, so this repo
// builds against a sibling checkout of the Kandev monorepo. See
// docs/development.md for the layout and the pinned tag.
replace github.com/kandev/kandev => ../kandev/apps/backend
