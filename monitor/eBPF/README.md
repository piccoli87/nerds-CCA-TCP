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
```
- Declara um mapa hash chamado flow_stats com chave u64 e valor struct flow_stats_t.
- A chave usada no código é o ponteiro do struct sock ((u64)sk), portanto cada socket tem sua entrada.
- O tamanho máximo do mapa é 16384 entradas.
- *Observação:* usar ponteiro do socket como chave é comum e eficiente, mas: ponteiros são únicos por socket enquanto o socket existir; se sockets fecharem e novos sockets alocarem a mesma addr de memória, entradas antigas podem confundir se não forem limpas.

# 3) 4) Helper try_fill_addr
```
static inline void try_fill_addr(struct flow_stats_t *s, struct sock *sk) {
    if (s->addr.proto != 0) return;

    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;

    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    s->addr.saddr = saddr;
    s->addr.daddr = daddr;
    s->addr.sport = sport;
    s->addr.dport = dport;
    s->addr.proto = IPPROTO_TCP;
}
```
- Tenta preencher os campos de endereço/porta somente se ainda não preenchidos (proto != 0 usado como flag).
- Usa bpf_probe_read_kernel para ler campos seguros dentro de struct sock.
- Importante:
    - sk->__sk_common.skc_dport normalmente está em ordem de rede (__be16). O código escreve esse valor diretamente em dport sem ntohs.     - Portanto, a porta pode aparecer em byte order de rede — é necessário usar conversão (bpf_ntohs / ntohs) se for preciso o valor legível.
    - skc_num é o número local (host order na sock?) — comportamentos podem variar; sempre verificar kernel version/endianness.
    - Esse helper só trata IPv4 – não considera IPv6 (sk->__sk_common tem campos diferentes para v6).
    - Leitura direta de campos internos do kernel pode falhar ou ficar inconsistente entre versões do kernel — ver seção CO-RE abaixo.

# 5) Helper try_read_tcp_metrics
```
static inline void try_read_tcp_metrics(struct flow_stats_t *s, struct sock *sk) {
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    u32 srtt_raw = 0;
    u32 cwnd = 0;

    bpf_probe_read_kernel(&srtt_raw, sizeof(srtt_raw), &tp->srtt_us);
    bpf_probe_read_kernel(&cwnd, sizeof(cwnd), &tp->snd_cwnd);

    s->srtt_us = srtt_raw;
    s->rtt_us = srtt_raw >> 3;
    s->cwnd = cwnd;
}
```
- Faz um cast do struct sock * para struct tcp_sock * e tenta ler srtt_us e snd_cwnd.
- srtt_raw: o código assume que o campo do kernel pode estar escalado (historicamente o RTTY/RTO internalmente foi representado com escala, por isso o comentário e >>3).
- Salva o srtt_raw e uma versão convertida rtt_us = srtt_raw >> 3 (aproximação).
- cwnd é lido diretamente (é medido em segmentos MSS normalmente).
- *Cuidados:*
    - Nem sempre é seguro fazer cast direto (struct tcp_sock *)sk — offsets e nomes de campos podem mudar entre versões. Em programas modernos recomenda-se usar BPF CO-RE (BPF_CORE_READ) para portabilidade entre kernels.
    - tp->srtt_us pode não existir ou mudar de nome/semântica entre versões do kernel; portanto use CO-RE ou proteja por verificações de versão.
