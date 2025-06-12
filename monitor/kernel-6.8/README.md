# Como compilar e carregar o módulo:
## Comandos para compilação:
**No diretório com os arquivos tcp_monitor.c e Makefile, excute:**
*sudo make*                       

**Para carregar o módulo, execute:**
*sudo insmod tcp_monitor.ko*   

**Para ver mensagens do kernel, execute:**
*sudo dmesg*                       

**Para visualizar as métricas coletadas, execute:**
*cat /proc/tcp_metrics*         

**Para remover o módulo, execute:**
*sudo rmmod tcp_monitor*        


