// Package launch implements the first-run (M0) launcher and exec.stop receiver
// selected by docs/design/first-run-launch-stop.md: closed launch-op/1 intake,
// an operator-installed protected start gate, the shared helper lock, the
// generation journal as the only generation authority, the root start receipt
// before verified privilege drop, committed-start A one-start accounting, and
// account-wide stop with the D5a absence proof over the real, effective and
// saved UID. It never creates, bumps or retires an account and never evaluates
// dispatcher policy or grants; those stay with their owners.
package launch
