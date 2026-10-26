// Package store is where the plugin keeps what it owns in Kandev: one Host
// state document each for the host registry, the egress policy, the secret
// index, the hosts' last checks, the root certificate and the API URL last
// seen, and the plugin secret store for every key and secret value. It is the
// only package that knows a state key, a secret key or a document's layout.
//
// Each store serializes its own read-modify-write cycles: Host state has no
// compare-and-swap.
package store
