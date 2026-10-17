// Package sshx is the SSH transport to sandbox hosts: the plugin's key, host
// key pinning, one shared connection per host, and the command-line quoting
// the host's forced command expects. It knows nothing about msbctl verbs.
package sshx

import (
	"regexp"
	"strings"
)

// unsafeChar matches what Python's shlex.quote treats as needing quotes. Its
// pattern is compiled with re.ASCII there; Go's \w is ASCII-only, so a
// non-ASCII letter is unsafe on both sides.
var unsafeChar = regexp.MustCompile(`[^\w@%+=:,./-]`)

// Quote quotes one argument exactly as Python's shlex.quote does. SSH sends
// a command as one string, and `msbctl host serve` splits it again with
// shlex.split, so the two sides must agree byte for byte.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	if !unsafeChar.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// Join is shlex.join: each argument quoted, separated by one space.
func Join(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = Quote(a)
	}
	return strings.Join(quoted, " ")
}
