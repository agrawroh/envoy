dynamic modules: fixed the network and UDP filters leaving ``worker_index_`` uninitialized. The
network filter parses the index out of the dispatcher name, and neither the format check nor the
parse failure returns, while ``absl::SimpleAtoi`` leaves its output unspecified when it fails. A
malformed dispatcher name therefore left the index indeterminate, and a module keys per-worker state
on it. The index now parses into a local and is only published when the parse succeeds, both families
declare it with a zero initializer, and the listener filter already did.
