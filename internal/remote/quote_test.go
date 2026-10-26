package remote_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"kandev-plugin-microsandbox/internal/remote"
)

func TestQuoteMatchesShlexQuote(t *testing.T) {
	// Expected values are Python 3's shlex.join output for the same argv.
	got := remote.Join([]string{"msbctl", "kandev", "provision", "k-env 1", "it's", "", "a=b,c:d/e@f%g+h", "é", "$HOME;rm"})
	assert.Equal(t, `msbctl kandev provision 'k-env 1' 'it'"'"'s' '' a=b,c:d/e@f%g+h 'é' '$HOME;rm'`, got)
}

// The generic verbs' argv as `host serve --kandev` admits them; a name from
// the record is a plain token, so nothing is quoted.
func TestGenericVerbCommandLines(t *testing.T) {
	for argv, want := range map[string]string{
		"ls":    "msbctl ls --json",
		"show":  "msbctl show k-6f1c2b9e --json",
		"stop":  "msbctl stop k-6f1c2b9e --json",
		"purge": "msbctl purge k-6f1c2b9e -y --json",
	} {
		args := map[string][]string{
			"ls":    {"msbctl", "ls", "--json"},
			"show":  {"msbctl", "show", "k-6f1c2b9e", "--json"},
			"stop":  {"msbctl", "stop", "k-6f1c2b9e", "--json"},
			"purge": {"msbctl", "purge", "k-6f1c2b9e", "-y", "--json"},
		}[argv]
		assert.Equal(t, want, remote.Join(args), argv)
	}
}
