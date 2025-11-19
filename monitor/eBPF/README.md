# _tcp_stats_sockkey.c_

## 1) Cabeçalho e compatibilidade
```
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <bcc/proto.h>

#pragma clang diagnostic ignored "-Wmacro-redefined"

/* Compat: fallback para bpf_probe_read_kernel se necessário */
#ifndef bpf_probe_read_kernel
# define bpf_probe_read_kernel(dst, size, src) bpf_probe_read(dst, size, src)
#endif
```
- Inclui cabeçalhos necessários para tipos kernel (struct sock, sk_buff, tcp_sock, helpers BPF do BCC).

- #pragma apenas suprime warning de redefinição de macros.

- O bloco `#ifndef` garante compatibilidade: em kernels/ambientes mais antigos onde bpf_probe_read_kernel não existe, ele usa bpf_probe_read como fallback. Isso permite carregar o programa em várias versões do kernel/BPF toolchains.

## 2) Estruturas de dados
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

## 3) Mapa BPF
```
BPF_HASH(flow_stats, u64, struct flow_stats_t, 16384);
```
- Declara um mapa hash chamado flow_stats com chave u64 e valor struct flow_stats_t.
- A chave usada no código é o ponteiro do struct sock ((u64)sk), portanto cada socket tem sua entrada.
- O tamanho máximo do mapa é 16384 entradas.
- *Observação:* usar ponteiro do socket como chave é comum e eficiente, mas: ponteiros são únicos por socket enquanto o socket existir; se sockets fecharem e novos sockets alocarem a mesma addr de memória, entradas antigas podem confundir se não forem limpas.

## 4) Helper try_fill_addr
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

## 5) Helper try_read_tcp_metrics
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
- _*Cuidados:*_
    - Nem sempre é seguro fazer cast direto (struct tcp_sock *)sk — offsets e nomes de campos podem mudar entre versões. Em programas modernos recomenda-se usar BPF CO-RE (BPF_CORE_READ) para portabilidade entre kernels.
    - tp->srtt_us pode não existir ou mudar de nome/semântica entre versões do kernel; portanto use CO-RE ou proteja por verificações de versão.

## 6) Kprobe: tcp_sendmsg
```
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    if (!sk) return 0;
    u64 sk_ptr = (u64)sk;
    struct flow_stats_t zero = {};
    struct flow_stats_t *s = flow_stats.lookup_or_init(&sk_ptr, &zero);
    if (!s) return 0;

    try_fill_addr(s, sk);

    __sync_fetch_and_add(&s->pkts_sent, 1);
    __sync_fetch_and_add(&s->bytes_sent, (u64)size);

    try_read_tcp_metrics(s, sk);

    s->last_seen_ns = bpf_ktime_get_ns();
    return 0;
}
```
- Anexado via BCC (nome kprobe__tcp_sendmsg é convenção do BCC para auto-attach).
- Para cada chamada de tcp_sendmsg,:
    - obtém (ou cria) uma entrada no mapa usando a chave sk_ptr;
    - preenche endereço se necessário;
    - incrementa pkts_sent (nota: não necessariamente um pacote físico enviado na rede — tcp_sendmsg é uma função de envio de mensagem ao TCP, pode corresponder a vários segmentos dependendo do MSS/segmentação);
    - incrementa bytes_sent com size (o parâmetro recebido pelo kernel);
    - atualiza métricas TCP (srtt/cwnd) e timestamp (bpf_ktime_get_ns() retorna tempo monotônico em ns).
- lookup_or_init inicializa com zero se não existir; retorna ponteiro para o valor no mapa.

## 7) Kprobe: tcp_retransmit_skb
```
int kprobe__tcp_retransmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if (!sk) return 0;
    u64 sk_ptr = (u64)sk;
    struct flow_stats_t zero = {};
    struct flow_stats_t *s = flow_stats.lookup_or_init(&sk_ptr, &zero);
    if (!s) return 0;

    try_fill_addr(s, sk);

    __sync_fetch_and_add(&s->retransmits, 1);

    try_read_tcp_metrics(s, sk);

    s->last_seen_ns = bpf_ktime_get_ns();
    return 0;
}
```
- Executa quando kernel retransmite um skb.
- Incrementa contador de retransmissões e lê métricas tcp para correlacionar retransmissões com rtt/cwnd naquele momento.
- Bom para detectar quando a retransmissão coincide com aumento de RTT ou redução de cwnd.

## 8) Kprobe: tcp_set_state
```
int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    if (!sk) return 0;
    u64 sk_ptr = (u64)sk;
    struct flow_stats_t zero = {};
    struct flow_stats_t *s = flow_stats.lookup_or_init(&sk_ptr, &zero);
    if (!s) return 0;

    try_fill_addr(s, sk);

    s->last_state = state;

    try_read_tcp_metrics(s, sk);

    s->last_seen_ns = bpf_ktime_get_ns();
    return 0;
}
```
- Chamada quando o estado da conexão TCP muda. Útil para saber transições (ex: ESTABLISHED → CLOSE) e para correlacionar estado com srtt/cwnd/retransmits.
- Armazena state bruto (número). Se quiser legibilidade, o usuário precisa mapear esses inteiros para constantes (p.ex. TCP_ESTABLISHED).

## 9) Observações operacionais e limitações
**1. Endianess das portas:** sk->__sk_common.skc_dport é normalmente __be16 (big-endian). O código grava sem conversão — isso pode levar a portas numéricas trocadas. Use bpf_ntohs() se quiser porto em host order e legível.
**2. IPv6 não tratado:** o código só lê skc_rcv_saddr/skc_daddr (IPv4). Para suportar IPv6 é preciso tratar sk_v6_* ou checar sk->sk_family.
**3. Portabilidade entre kernels:** acessar campos internos de struct tcp_sock diretamente (cast) pode quebrar entre versões. Recomenda-se usar CO-RE (BPF_CORE_READ) ou macros do libbpf para resolver offsets em tempo de compilação/execution.
**4. Verifier / segurança:** o programa evita loops e usa apenas leituras e incrementos simples — em geral isso passa no verificador. Contudo, leituras de tcp_sock via cast podem ser recusadas dependendo de verificações de tipo/offset.
**5. Map growth / limpeza:** entradas são criadas por socket pointer; o código não remove entradas quando socket fecha — pode acumular entradas para sockets mortos. Sugestão: no kprobe de tcp_set_state quando state == TCP_CLOSE (ou em inet_release), remover a entrada do mapa.
**6. Uso de contador atômico:** __sync_fetch_and_add() é sintaxe aceita pelo BCC para tradução em atomics em eBPF; ok, mas considere bpf_map_update_elem em cenários diferentes ou mapas per-cpu para reduzir contention.
**7. Granularidade das métricas:**
    - pkts_sent incrementa em tcp_sendmsg — pode não corresponder 1:1 a pacotes na wire (segmentação/TSO/GSO podem agrupar).
    - bytes_sent soma size do tcp_sendmsg — útil, mas para bytes realmente transmitidos poderia observar skb/netdev hooks.
**8. srtt_us sem garantia absoluta:** campo srtt_us e a conversão >>3 são heurísticas. A representação exata do kernel muda ao longo do tempo — recomendo verificar a definição do campo srtt_us na versão do kernel alvo.

## 10) Sugestões de melhorias práticas
- **Converter portas:** aplicar bpf_ntohs(dport) antes de armazenar.
- **Suportar IPv6 e checar:** sk->sk_family:
    - Para IPv6 lembrar de ler sk->sk_v6_rcv_saddr / sk->sk_v6_daddr.
- **Usar CO-RE / BPF_CORE_READ** para portabilidade entre kernels (libbpf/more recent BPF toolchains).
- **Limpeza de mapa:** remover entradas quando socket fecha (por exemplo, em tcp_set_state quando state == TCP_CLOSE) para evitar vazamento de entradas.
- **Considerar per-CPU maps** para contadores de alta frequência (p.ex. BPF_PERCPU_HASH ou BPF_PERCPU_ARRAY) e reduzir contention e custo de operações atômicas.
- **Expôr as métricas para userland:** use bpftool map dump ou um programa BCC/python para ler o mapa e traduzir valores (conversão de portas, conversão srtt).
- **Documentar mapeamento de campos TCP:** adicionar comentários/constantes que traduzam last_state para nomes.

## 11) Como ler/interpretar os dados obtidos
- **pkts_sent** e **bytes_sent:** permitem estimar taxa emitida (diferença de bytes_sent/delta tempo).
- **retransmits:** diretamente indica eventos de retransmissão por socket.
- **srtt_us raw** e **rtt_us** convertido: correlacione aumento de rtt com retransmissões (o código já lê srtt nos três probes).
- **cwnd:** indica a janela de congestionamento atual (em MSS). Queda súbita de cwnd junto a retransmissões sugere perda detectada.
- **last_seen_ns** permite ordenar eventos e calcular deltas temporais.


# _tcp_stats_monitor_sockkey.py_

## 1) Visão geral rápida

O script é um monitor userland escrito com BCC (Python) que abre o mapa BPF _flow_stats_ criado pelo programa tcp_stats_sockkey.c e imprime periodicamente (a cada 1s) estatísticas por conexão TCP identificada pela chave u64 (ponteiro do struct sock).
Ele:
- carrega/compila o código BPF (arquivo tcp_stats_sockkey.c),
- obtém a tabela flow_stats exposta pelo BPF,
- itera sobre as entradas do mapa e formata as informações (IP, porta, pkts, bytes, retransmissões, RTT, cwnd, estado),
- imprime em texto legível no terminal.

## 2) Cabeçalho e imports
```
from bcc import BPF
import socket, struct, time, sys
```
- BCC fornece a API para compilar/carregar/consultar mapas e programas BPF.
- socket/struct usados para conversões de endereços e portas.
- time e sys para controle de loop e saída.

## 3) Constante do arquivo BPF
```
BPF_SOURCE = "tcp_stats_sockkey.c"
```
- Nome do arquivo C com o programa BPF. O script chama BPF(src_file=BPF_SOURCE) para compilar e carregar esse arquivo automaticamente. Portanto o arquivo deve estar no mesmo diretório (ou fornecer caminho completo).

## Função _ip_ntoa_be(addr)_
```
  def ip_ntoa_be(addr):
    try:
        return socket.inet_ntoa(struct.pack("<I", addr))
    except Exception:
        return socket.inet_ntoa(struct.pack(">I", addr))
```

- Objetivo: converter um u32 (IPv4) lido do mapa em string "a.b.c.d".
- Observação sobre endianness:
    - struct.pack("<I", addr) cria bytes little-endian; inet_ntoa espera um endereço em network byte order (big-endian).
    - A função tenta primeiro interpretar addr como little-endian; se dar erro, tenta big-endian. Isso é uma heurística porque, dependendo de como o BPF escreveu o u32, ele pode estar em ordens trocadas.
- Risco: essa heurística resolve muitos casos, mas não garante correção para todos. Melhor abordagem é garantir explicitamente a ordem no código BPF (ex.: armazenar em network order com htonl) ou aplicar socket.ntohl no monitor.

## Função _port_be16_to_host(p)_
```
def port_be16_to_host(p):
    try:
        return socket.ntohs(p & 0xffff)
    except Exception:
        return p
```
- Converte u16 possivelmente em network order (big-endian) para host order, usando ntohs.
- Faz p & 0xffff para garantir que o valor passado a ntohs seja 16 bits inteiros.
- Observação: no código BPF original, dport provavelmente foi gravado como __be16 (network order). Então essa conversão é necessária para exibir portas corretas.

## Função _state_name(state)_
```
def state_name(state):
    names = { 1: "ESTABLISHED", 2: "SYN_SENT", ... 11: "CLOSING", }
    return names.get(state, str(state))
```
- Mapeia valores inteiros de tcp_state para nomes legíveis.
- Se o estado não estiver no dicionário, retorna o inteiro convertido para string.

## Função principal _main()_: carregar BPF e abrir tabela
```
b = BPF(src_file=BPF_SOURCE)
table = b.get_table("flow_stats")
```
- BPF(...) compila e carrega o programa BPF. Se ocorrer erro (falta clang, permissões, verificador rejeitou, etc.) o script imprime erro e sai.
- b.get_table("flow_stats") obtém um objeto Table que permite iterar sobre as entradas do mapa BPF chamado flow_stats definido no código C (BPF_HASH(flow_stats,...)).

### Requisitos:

- rodar como root (ou via sudo) — carregar kprobes/BPF normalmente requer privilégios.
- ter bcc/python3-bcc, clang, linux-headers, etc. instalados.

## Loop principal: leitura periódica do mapa
```
while True:
    if len(table) == 0:
        print("[snapshot] sem fluxos observados ainda.")
    else:
        print("[snapshot]")

    for k, v in table.items():
        sk_ptr = int.from_bytes(bytes(k), byteorder="little")
        ...
```
- A cada iteração (1s), verifica se o mapa está vazio e imprime "[snapshot]".
- table.items() retorna pares (key, value):
    - k é um objeto que implementa __bytes__(); bytes(k) converte a chave para bytes crus. Depois int.from_bytes(..., little) transforma a chave em inteiro interpretando os bytes como little-endian — corresponde à forma como a chave foi escrita no BPF (o código BPF usa u64 sk_ptr = (u64)sk), portanto aqui a leitura little-endian costuma estar correta.
    - sk_ptr é o ponteiro do struct sock apresentado em hex ao usuário (útil para identificar sockets unicamente no mapa).
- v é a struct flow_stats_t (converted to a Python object por BCC) — seus campos são acessíveis como atributos (v.addr, v.pkts_sent, ...).

## Extração e conversões de campos
```
addr = v.addr
saddr = addr.saddr
daddr = addr.daddr
sport = addr.sport
dport = addr.dport
...
srtt_raw = getattr(v, "srtt_us", 0)
rtt_us = getattr(v, "rtt_us", 0)
cwnd = getattr(v, "cwnd", 0)
```
- Acessa campos da struct retornada pelo mapa.
- Usa getattr(..., 0) para compatibilidade caso a struct no mapa não contenha os campos mais novos (srtt_us, rtt_us, cwnd) — útil se você usar uma versão anterior do BPF que não define esses campos.
- Depois converte saddr/daddr em string com ip_ntoa_be, e portas com port_be16_to_host.
- Calcula rtt_ms e srtt_ms dividindo micros por 1000.

## Impressão formatada
```
print(
    f"sock=0x{sk_ptr:x} {s_ip}:{s_port} -> {d_ip}:{d_port} proto={proto} "
    f"pkts={pkts} bytes={bytes_sent} retr={retrans} "
    f"RTT={rtt_ms:.3f}ms (srtt_raw={srtt_raw}) srtt_ms={srtt_ms:.3f}ms "
    f"CWND={cwnd} MSS state={state_name(last_state)} last_seen_ns={last_seen_ns}"
)
```
- Mostra resumo por socket:
    - ponteiro do socket,
    - endereço origem/destino e portas,
    - protocolo,
    - contadores (pkts, bytes, retransmits),
    - RTT em ms e raw,
    - cwnd (unidade: MSS),
    - estado legível via state_name,
    - last_seen_ns (timestamp em ns — como foi escrito pelo BPF: bpf_ktime_get_ns()).
**Observação:** last_seen_ns é um timestamp monotônico em ns; para converter para tempo humano ou calcular latência desde o último evento você precisa comparar com time.monotonic_ns() ou time.time().

## Controle de loop e encerramento
- Ao finalizar com Ctrl-C, o KeyboardInterrupt é capturado para imprimir "Saindo" e terminar graciosamente.

## Execução — comandos práticos
1. Instale dependências (Debian/Ubuntu):
```
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc clang linux-headers-$(uname -r)
```
2. Coloque tcp_stats_sockkey.c e tcp_stats_monitor_sockkey.py no mesmo diretório.
3. Rode com privilégios de root:
```
sudo python3 tcp_stats_monitor_sockkey.py
```
O script tentará compilar/carregar o BPF automaticamente. Se o BPF for rejeitado pelo verifier, o script imprime o erro e sai.

## Exemplo de saída típica
```
eBPF carregado. Monitorando fluxos TCP (por sock pointer). Ctrl-C para sair.

[snapshot]
sock=0xffff9b48aab0 10.0.0.1:443 -> 10.0.0.2:53152 proto=6 pkts=42 bytes=58432 retr=1 RTT=12.345ms (srtt_raw=98765) srtt_ms=98.765ms CWND=10 MSS state=ESTABLISHED last_seen_ns=1234567890123456

```

