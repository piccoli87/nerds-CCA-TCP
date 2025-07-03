# Como compilar e carregar o módulo:
## Comandos para compilação:
**No diretório com os arquivos tcp_monitor.c e Makefile, excute:**
*sudo make*                       

**Para carregar o módulo, execute:**
*sudo insmod tcp_monitor.ko*   

**Se quiser passar filtros de IP:**
*sudo insmod tcp_monitor.ko src_ip=10.0.0.1 dst_ip=10.0.0.2*

**Para ver mensagens do kernel, execute:**
*sudo dmesg*                       

**Para visualizar as métricas coletadas, execute:**
*cat /proc/tcp_metrics*         
*cat /proc/tcp_metrics | tail -n 1*
**Para melhor alinhamento:**
*cat /proc/tcp_metrics | column -t*

**Para visualizar o cabeçalho e a última métrica, execute:**
*awk 'NR==1 {first=$0} {last=$0} END {print "First:", first; print "Last:", last}' /proc/tcp_metrics*

*awk 'NR==1 {first=$0} {buf[NR%3]=$0} END {print "First:", first; print "Second Last:", buf[(NR-1)%3]; print "Last:", buf[NR%3]}' /proc/tcp_metrics*

**Para remover o módulo, execute:**
*sudo rmmod tcp_monitor*        


# 🧩 Dados coletados:
| Coluna        | Significado                                                                                                                                              |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **SADDR**     | **Source Address** – Endereço IP de origem (host local).                                                                                                 |
| **DADDR**     | **Destination Address** – Endereço IP de destino (servidor ou peer remoto).                                                                              |
| **SPORT**     | **Source Port** – Porta TCP de origem.                                                                                                                   |
| **DPORT**     | **Destination Port** – Porta TCP de destino.                                                                                                             |
| **CWND**      | **Congestion Window** – Tamanho atual da janela de congestionamento (em segmentos). Indica o número de segmentos que o TCP pode enviar sem receber ACKs. |
| **SRTT**      | **Smoothed Round Trip Time** – Tempo médio de ida e volta suavizado (em microssegundos).                                                                 |
| **RTTVAR**    | **RTT Variance** – Variância do RTT (em microssegundos), usada para estimar o intervalo de retransmissão.                                                |
| **RET**       | **Retransmissions Out** – Número de segmentos TCP atualmente na fila de retransmissão. Indica se houve perda ou timeout.                                 |
| **SNDWND**    | **Send Window Size** – Tamanho do buffer de envio da aplicação (em bytes).                                                                               |
| **RCVWND**    | **Receive Window Size** – Tamanho do buffer de recepção da aplicação (em bytes).                                                                         |
| **TOS**       | **DSCP** 6 bits (Expedited Forwarding)                                                                                                                   |
|               | **ECN**  2 bits                                                                                                                                          |
| **ALG**       | **Algoritmo de Congestionamento** – Algoritmo TCP em uso (ex: `cubic`, `bbr`, `reno`).                                                                   |
| **TIMESTAMP** | Marca de tempo (em nanossegundos) obtida via `ktime_get_ns()` no momento da leitura do socket.                                                           |

## 🧠 Exemplo interpretado:

|**SADDR      |    DADDR       | SPORT  | DPORT | CWND|  SRTT  | RTTVAR | RET| SNDWND| RCVWND| DSCP  | ECN | ALG   |    TIMESTAMP**   |
| ------------|--------------- | -------| ----- | ----|--------|--------|----|-------|-------|-------|-----|----------------------_---|
|172.16.30.92 |  142.250.0.188 |  60772 |  5228 | 10  | 793322 | 290165 |  0 | 87380 | 87380 |       |     | cubic |  169516884622211 |

*a) Essa conexão TCP foi estabelecida entre o IP local 172.16.30.92 e o IP remoto 142.250.0.188, usando a porta de origem 60772 e a porta de destino 5228.*

*b) Está usando o algoritmo de congestionamento cubic.*

*c) A janela de congestionamento atual (cwnd) está em 10 segmentos.*

*d) O RTT médio estimado é de aproximadamente 793 ms, com variação de 290 ms.*

*e) Nenhuma retransmissão está pendente (RET = 0).*

*f) Os buffers de envio e recepção são 87380 bytes.*

