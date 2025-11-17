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

# 2) Estruturas de dados
```
struct flow_addr_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  proto;
    u8  pad[3];
};

struct flow_stats_t {
    struct flow_addr_t addr;
    u64 pkts_sent;
    u64 bytes_sent;
    u64 retransmits;
    u32 last_state;
    u64 last_seen_ns;

    /* Novas métricas */
    u32 srtt_us;    // valor cru (do kernel)
    u32 rtt_us;     // srtt_us convertido (divide por 8)
    u32 cwnd;       // snd_cwnd (unidade: MSS segments)
};

```
- flow_addr_t: armazena endereço origem/destino IPv4 (u32), portas (u16) e protocolo. Observação: é só para IPv4 (não trata IPv6).
- flow_stats_t: contém contadores/estatísticas por flow (na implementação o key do mapa será o ponteiro do struct sock). Campos:
  - pkts_sent, bytes_sent — acumuladores;
  - retransmits — contador de retransmissões;
  - last_state — último estado TCP observado (valores como TCP_ESTABLISHED, TCP_CLOSE etc);
  - last_seen_ns — timestamp (ns) do último evento;
  - srtt_us e rtt_us — srtt lido do kernel (o código mantém o raw e também converte com >>3, conforme comentário);
  - cwnd — snd_cwnd do tcp_sock.

# 3) Mapa BPF
```
BPF_HASH(flow_stats, u64, struct flow_stats_t, 16384);
``
- Declara um mapa hash chamado flow_stats com chave u64 e valor struct flow_stats_t.
- A chave usada no código é o ponteiro do struct sock ((u64)sk), portanto cada socket tem sua entrada.
- O tamanho máximo do mapa é 16384 entradas.
- *Observação:* usar ponteiro do socket como chave é comum e eficiente, mas: ponteiros são únicos por socket enquanto o socket existir; se sockets fecharem e novos sockets alocarem a mesma addr de memória, entradas antigas podem confundir se não forem limpas.

