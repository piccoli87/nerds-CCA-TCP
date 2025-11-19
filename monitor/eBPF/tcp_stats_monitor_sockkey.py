#!/usr/bin/env python3
# tcp_stats_monitor_sockkey.py
# Monitor que lê o map flow_stats (chave: u64 sock ptr) e imprime stats por conexão.
# Espera que o BPF seja compilado a partir de "tcp_stats_sockkey.c"

from bcc import BPF
import socket, struct, time, sys, os, bisect

BPF_SOURCE = "tcp_stats_sockkey.c"

def ip_ntoa_be(addr):
    try:
        return socket.inet_ntoa(struct.pack("<I", addr))
    except Exception:
        return socket.inet_ntoa(struct.pack(">I", addr))

def port_be16_to_host(p):
    try:
        return socket.ntohs(p & 0xffff)
    except Exception:
        return p

def state_name(state):
    names = {
        1: "ESTABLISHED",
        2: "SYN_SENT",
        3: "SYN_RECV",
        4: "FIN_WAIT1",
        5: "FIN_WAIT2",
        6: "TIME_WAIT",
        7: "CLOSE",
        8: "CLOSE_WAIT",
        9: "LAST_ACK",
        10: "LISTEN",
        11: "CLOSING",
    }
    return names.get(state, str(state))

def system_default_cc():
    try:
        with open("/proc/sys/net/ipv4/tcp_congestion_control") as f:
            return f.read().strip()
    except Exception:
        return ""

# Carrega /proc/kallsyms em memória para resolver endereços próximos (heurística)
def load_kallsyms():
    ks = []
    names = []
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.strip().split(None, 2)
                if len(parts) >= 3:
                    addr_s, _, name = parts
                    try:
                        addr = int(addr_s, 16)
                    except:
                        continue
                    ks.append(addr)
                    names.append(name.strip())
        # ordenar por endereço (deve já vir ordenado, mas garantimos)
        combined = sorted(zip(ks, names), key=lambda x: x[0])
        ks = [c[0] for c in combined]
        names = [c[1] for c in combined]
        return ks, names
    except Exception:
        return [], []

# Resolve um ponteiro aproximado para nome (procura símbolo exato ou mais próximo abaixo)
def resolve_ptr_name(ptr, ks, names):
    if not ptr or not ks:
        return ""
    # busca exata
    i = bisect.bisect_left(ks, ptr)
    if i < len(ks) and ks[i] == ptr:
        return names[i]
    # se não exato, pega o símbolo anterior (mais próximo abaixo), se estiver razoavelmente perto
    j = i-1
    if j >= 0:
        sym_addr = ks[j]
        # heurística: aceitar se a diferença for pequena (por ex. < 4096 bytes)
        if abs(ptr - sym_addr) < 4096:
            return names[j] + " (+offset)"
    return ""

def main():
    try:
        b = BPF(src_file=BPF_SOURCE)
    except Exception as e:
        print("Erro ao compilar/carregar BPF:", e)
        sys.exit(1)

    try:
        table = b.get_table("flow_stats")
    except Exception as e:
        print("Erro ao abrir tabela flow_stats:", e)
        sys.exit(1)

    print("eBPF carregado. Monitorando fluxos TCP (por sock pointer). Ctrl-C para sair.\n")

    ks, names = load_kallsyms()
    if ks:
        print("kallsyms carregado, resolução de ponteiros tentada.")
    else:
        print("kallsyms não disponível ou não carregado; fallbacks serão usados.")

    try:
        while True:
            if len(table) == 0:
                print("[snapshot] sem fluxos observados ainda.")
            else:
                print("[snapshot]")

            for k, v in table.items():
                # chave é u64 (sock pointer) - obter como inteiro
                sk_ptr = int.from_bytes(bytes(k), byteorder="little")

                addr = v.addr
                saddr = addr.saddr
                daddr = addr.daddr
                sport = addr.sport
                dport = addr.dport
                proto = addr.proto

                pkts = v.pkts_sent
                bytes_sent = v.bytes_sent
                retrans = v.retransmits
                last_state = v.last_state
                last_seen_ns = v.last_seen_ns

                # Novas métricas
                srtt_raw = getattr(v, "srtt_us", 0)   # raw tal como lido do kernel
                rtt_us = getattr(v, "rtt_us", 0)      # conversão feita no BPF (raw >> 3)
                cwnd = getattr(v, "cwnd", 0)

                # ponteiro para tcp_congestion_ops (lido no BPF)
                cc_ops_ptr = getattr(v, "cc_ops_ptr", 0)

                # conversões IP/porta
                try:
                    s_ip = ip_ntoa_be(saddr)
                    d_ip = ip_ntoa_be(daddr)
                except Exception:
                    s_ip = str(saddr)
                    d_ip = str(daddr)
                s_port = port_be16_to_host(sport)
                d_port = port_be16_to_host(dport)

                # formatar RTT em ms
                rtt_ms = (rtt_us / 1000.0) if rtt_us else 0.0
                srtt_ms = ((srtt_raw >> 3 )/ 1000.0) if srtt_raw else 0.0
                # srtt_ms -> RTT suavizado (smoothed RTT) em milissegundos.

                # tentar resolver ponteiro para nome via kallsyms
                cc_name = resolve_ptr_name(cc_ops_ptr, ks, names)
                if not cc_name:
                    # fallback: se não resolvido, usa o default do sistema
                    cc_name = system_default_cc()

                # print(
                #     f"sock=0x{sk_ptr:x} {s_ip}:{s_port} -> {d_ip}:{d_port} proto={proto} "
                #     f"pkts={pkts} bytes={bytes_sent} retr={retrans} "
                #     f"RTT={rtt_ms:.3f}ms (srtt_raw={srtt_raw}) srtt_ms={srtt_ms:.3f}ms "
                #     f"CWND={cwnd} MSS CC_PTR=0x{cc_ops_ptr:x} CC={cc_name} "
                #     f"state={state_name(last_state)} last_seen_ns={last_seen_ns}"
                # )

                print(
                    f"{s_ip}:{s_port} -> {d_ip}:{d_port} "
                    f"pkts={pkts} retr={retrans} "
                    f"RTT={rtt_ms:.3f}ms srtt_ms={srtt_ms:.3f}ms "
                    f"CWND={cwnd} MSS CC={cc_name} "
                    f"state={state_name(last_state)} last_seen_ns={last_seen_ns}"
                )

            print("")
            time.sleep(0.3)
    except KeyboardInterrupt:
        print("Saindo")
        pass

if __name__ == "__main__":
    main()
