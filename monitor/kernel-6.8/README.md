# Como compilar e carregar o módulo:
## Comandos para compilação:
**No diretório com os arquivos tcp_monitor.c e Makefile, excute:**
make                           # Compila

**Para carregar o módulo, execute:**
sudo insmod tcp_monitor.ko     *Carrega o módulo*

**Para ver mensagens do kernel, execute:**
sudo dmesg                          *Ver mensagens do kernel*

**Para visualizar as métricas coletadas, execute:**
cat /proc/tcp_metrics          *Ver métricas coletadas*

**Para remover o módulo, execute:**
sudo rmmod tcp_monitor         *Remove o módulo*


