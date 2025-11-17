# 1) Cabeçalho e compatibilidade
```
`#include <uapi/linux/ptrace.h>`
`#include <linux/skbuff.h>`
`#include <net/sock.h>`
`#include <linux/tcp.h>`
`#include <bcc/proto.h>`

`#pragma clang diagnostic ignored "-Wmacro-redefined"`

/* Compat: fallback para bpf_probe_read_kernel se necessário */
`#ifndef bpf_probe_read_kernel`
`# define bpf_probe_read_kernel(dst, size, src) bpf_probe_read(dst, size, src)`
`#endif`
```
