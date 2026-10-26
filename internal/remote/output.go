package remote

// Output is what one setup command printed. Unlike msbctl's kandev answers,
// stderr is kept: it is the operator's own machine, and an installer's error
// is the only way to say why a step failed.
type Output struct {
	Stdout []byte
	Stderr []byte
	Exit   int
}

// AdminAuth is an operator's own login to a machine, given once to set it up.
// It is secret: it lives only in memory for one setup, never in state, argv,
// a log line or a response.
type AdminAuth struct {
	PrivateKeyPEM string
	Passphrase    string
	Password      string
}
