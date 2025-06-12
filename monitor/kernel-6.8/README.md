Como compilar e carregar o módulo:

make                           # Compila

sudo insmod tcp_monitor.ko     # Carrega o módulo

dmesg                          # Ver mensagens do kernel

cat /proc/tcp_metrics          # Ver métricas coletadas

sudo rmmod tcp_monitor         # Remove o módulo


