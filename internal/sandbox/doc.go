// Package sandbox owns the decisions behind Kandev's executor provider calls:
// what a resource's state records, what a bootstrap must carry, what a
// provision asks of a host, where a new sandbox goes (or which host already
// has it), and how a host's answer maps onto Kandev's states and error codes.
// It reaches hosts through the Host port and knows nothing of the SDK: the
// transport turns its values into descriptors and responses.
package sandbox
