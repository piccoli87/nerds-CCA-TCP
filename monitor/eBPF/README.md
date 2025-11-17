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
- Inclui cabeçalhos necessários para tipos kernel (struct sock, sk_buff, tcp_sock, helpers BPF do BCC).

- `#pragma apenas suprime warning de redefinição de macros.`

- O bloco `#ifndef` garante compatibilidade: em kernels/ambientes mais antigos onde bpf_probe_read_kernel não existe, ele usa bpf_probe_read como fallback. Isso permite carregar o programa em várias versões do kernel/BPF toolchains.
