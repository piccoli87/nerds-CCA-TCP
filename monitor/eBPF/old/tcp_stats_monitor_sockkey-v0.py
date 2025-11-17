#!/usr/bin/env python3
# tcp_stats_monitor_sockkey.py
# Lê o map flow_stats (chave: u64 sock ptr) e imprime stats por conexão.

from bcc import BPF
import socket, struct, time, sys

BPF_SOURCE = "tcp_stats_sockkey-v0.c"

def ip_ntoa_le(addr):
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
    # estados TCP como no kernel (partial list)
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

    try:
        while True:
            if len(table) == 0:
                print("[snapshot] sem fluxos observados ainda.")
            else:
                print("[snapshot]")
            for k, v in table.items():
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

                # convert ports/ips
                try:
                    s_ip = ip_ntoa_le(saddr)
                    d_ip = ip_ntoa_le(daddr)
                except Exception:
                    s_ip = str(saddr)
                    d_ip = str(daddr)
                dport_host = port_be16_to_host(dport)

                print(f"sock=0x{sk_ptr:x} {s_ip}:{sport} -> {d_ip}:{dport_host} proto={proto} "
                      f"pkts={pkts} bytes={bytes_sent} retrans={retrans} state={state_name(last_state)} last_seen_ns={last_seen_ns}")

            print("")
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("Saindo")
        pass

if __name__ == "__main__":
    main()
