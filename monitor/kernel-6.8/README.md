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


