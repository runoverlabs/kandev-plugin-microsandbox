// Package remote is the shared vocabulary of running commands on a sandbox
// host: the command-line quoting the host's forced command expects, what one
// command printed, and the kinds of failure to reach a host. The SSH
// transport (internal/sshx) produces them; host setup, the host check and
// the transport's messages consume them without knowing SSH.
//
// Standard library only.
package remote
