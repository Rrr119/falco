# eBPF Event Source

Falco exposes BPF syscall events through a dedicated logical event source named
`ebpf`. The source is backed by the same inspector and capture thread as the
`syscall` source, so enabling it does not open another driver, allocate another
buffer, or duplicate the event stream.

## Event coverage

The `ebpf` source accepts both BPF syscall event ABIs supported by
falcosecurity/libs:

- `PPME_SYSCALL_BPF_E` and `PPME_SYSCALL_BPF_X`
- `PPME_SYSCALL_BPF_2_E` and `PPME_SYSCALL_BPF_2_X`

All four event types have the Falco event name `bpf`. Rules can therefore use
`evt.type=bpf` while selecting `source: ebpf`, and they will match modern eBPF
drivers regardless of which ABI the driver emits.

The source is active whenever the `syscall` source is enabled. It is not a
plugin source and cannot produce events on its own.

## Rules

`config/falco-ebpf_rules.yaml` is installed under
`/etc/falco/rules.d`. The packaged `falco.yaml` already loads that directory.
When running from a source tree, pass the file explicitly:

```sh
falco -r config/falco-ebpf_rules.yaml
```

The bundled rule detects `BPF_PROG_LOAD` calls made by containerized processes.
The `ebpf_trusted_loader_processes` list can be extended with agents that are
expected to load eBPF programs in your environment. To audit every load,
remove the `proc.name` exclusion from the rule condition.

## Output

Alerts from the `ebpf` source use the same `falco_outputs` path as every other
source. Text and JSON schemas are unchanged; JSON output reports the logical
source while retaining the standard alert fields:

```json
{
  "source": "ebpf",
  "rule": "eBPF Program Loaded in Container",
  "priority": "Warning",
  "output_fields": {
    "evt.type": "bpf",
    "evt.arg.cmd": "BPF_PROG_LOAD",
    "container.id": "0123456789ab"
  }
}
```

## Testing

Unit tests verify source classification, rule compilation, event selection,
and the standard output field set:

```sh
cmake --build build --target falco_unit_tests
./build/unit_tests/falco_unit_tests --gtest_filter='EbpfEventSource.*'
```

The e2e event-generator suite also contains
`ebpf_program_loaded_in_container.yaml`, which asserts the `ebpf` source,
priority, and output fields.
