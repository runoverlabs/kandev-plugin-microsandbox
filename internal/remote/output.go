package remote

// Output is what one setup command printed. Unlike msbctl's kandev answers,
// stderr is kept: it is the operator's own machine, and an installer's error
// is the only way to say why a step failed.
type Output struct {
	Stdout []byte
	Stderr []byte
	Exit   int
}
