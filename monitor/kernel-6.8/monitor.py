#!/usr/bin/env python3
import subprocess
import time
import sys
import os

# Lista de todas as métricas disponíveis
ALL_METRICS = [
    "SADDR", "DADDR", "SPORT", "DPORT", "CWND", "SRTT", "RTTVAR", 
    "RET", "SNDWND", "RCVWND", "DSCP", "ECN", "ALG", "TIMESTAMP"
]

def get_tcp_metrics():
    """
    Executa o comando para obter as métricas TCP e retorna a saída
    """
    try:
        # Executa o comando e captura a saída
        result = subprocess.run(
            ['cat', '/proc/tcp_metrics'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Erro ao executar comando: {e}"
    except FileNotFoundError:
        return "Erro: Arquivo /proc/tcp_metrics não encontrado"
    except Exception as e:
        return f"Erro inesperado: {e}"

def filter_metrics(metrics_output, selected_metrics):
    """
    Filtra as métricas baseado na seleção do usuário
    """
    if not metrics_output.strip():
        return metrics_output
    
    lines = metrics_output.strip().split('\n')
    
    # Se for -all, retorna todas as métricas
    if "all" in selected_metrics:
        return metrics_output
    
    # Encontra o cabeçalho e as linhas de dados
    header_line = None
    data_lines = []
    
    for line in lines:
        if any(metric in line for metric in ALL_METRICS):
            header_line = line
        else:
            data_lines.append(line)
    
    if not header_line:
        return metrics_output
    
    # Divide o cabeçalho em colunas
    header_parts = header_line.split()
    
    # Encontra os índices das colunas selecionadas
    selected_indices = []
    filtered_header = []
    
    for i, metric in enumerate(header_parts):
        if metric in selected_metrics:
            selected_indices.append(i)
            filtered_header.append(metric)
    
    if not selected_indices:
        return "Nenhuma métrica selecionada corresponde ao cabeçalho encontrado."
    
    # Filtra as linhas de dados
    filtered_lines = []
    for line in data_lines:
        if line.strip():
            parts = line.split()
            filtered_parts = [parts[i] for i in selected_indices if i < len(parts)]
            filtered_lines.append(' '.join(filtered_parts))
    
    # Monta a saída filtrada
    result = ' '.join(filtered_header) + '\n'
    result += '\n'.join(filtered_lines)
    
    return result

def display_metrics(selected_metrics=None):
    """
    Exibe as métricas TCP a cada segundo (com limpeza de tela)
    """
    if selected_metrics is None:
        selected_metrics = ["all"]
    
    try:
        while True:
            # Limpa a tela
            os.system('clear' if os.name == 'posix' else 'cls')
            
            # Obtém as métricas atuais
            raw_metrics = get_tcp_metrics()
            
            # Filtra as métricas se necessário
            if "all" in selected_metrics:
                metrics = raw_metrics
            else:
                metrics = filter_metrics(raw_metrics, selected_metrics)
            
            # Exibe com timestamp
            print(f"=== Métricas TCP - {time.strftime('%H:%M:%S')} ===")
            if "all" not in selected_metrics:
                print(f"Métricas selecionadas: {', '.join(selected_metrics)}")
            print(metrics)
            print("=" * 50)
            print("Pressione Ctrl+C para sair...")
            
            # Aguarda 1 segundo
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\nMonitoramento encerrado.")
    except Exception as e:
        print(f"Erro durante o monitoramento: {e}")

def display_metrics_simple(selected_metrics=None):
    """
    Versão alternativa que não limpa a tela, apenas adiciona novas linhas
    """
    if selected_metrics is None:
        selected_metrics = ["all"]
    
    try:
        print("Iniciando monitoramento de métricas TCP...")
        if "all" not in selected_metrics:
            print(f"Métricas selecionadas: {', '.join(selected_metrics)}")
        print("Pressione Ctrl+C para sair\n")
        
        while True:
            raw_metrics = get_tcp_metrics()
            
            # Filtra as métricas se necessário
            if "all" in selected_metrics:
                metrics = raw_metrics
            else:
                metrics = filter_metrics(raw_metrics, selected_metrics)
            
            print(f"\n--- Métricas TCP - {time.strftime('%H:%M:%S')} ---")
            if "all" not in selected_metrics:
                print(f"Métricas: {', '.join(selected_metrics)}")
            print(metrics)
            print("-" * 40)
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado.")

def display_metrics_sequential(selected_metrics=None):
    """
    Versão que imprime todas as capturas sequencialmente sem limpar tela
    """
    if selected_metrics is None:
        selected_metrics = ["all"]
    
    try:
        print("Iniciando monitoramento sequencial de métricas TCP...")
        if "all" not in selected_metrics:
            print(f"Métricas selecionadas: {', '.join(selected_metrics)}")
        print("Todas as capturas serão exibidas sequencialmente")
        print("Pressione Ctrl+C para sair\n")
        
        capture_count = 0
        
        while True:
            raw_metrics = get_tcp_metrics()
            
            # Filtra as métricas se necessário
            if "all" in selected_metrics:
                metrics = raw_metrics
            else:
                metrics = filter_metrics(raw_metrics, selected_metrics)
            
            capture_count += 1
            
            print(f"\n--- Captura #{capture_count} - {time.strftime('%H:%M:%S')} ---")
            if "all" not in selected_metrics:
                print(f"Métricas: {', '.join(selected_metrics)}")
            print(metrics)
            print("-" * 50)
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\nMonitoramento encerrado. Total de {capture_count} capturas realizadas.")

def show_usage():
    """
    Exibe o uso correto do script
    """
    print("Uso: python3 monitor.py [MODO] [MÉTRICAS]")
    print("\nModos:")
    print("  -last     : Exibe apenas a última captura (limpa tela a cada atualização)")
    print("  -seg      : Exibe todas as capturas sequencialmente")
    print("  --simple  : Modo simples sem limpar tela")
    print("  sem parâmetro: Usa o modo padrão (-last)")
    print("\nMétricas:")
    print("  -all      : Exibe todas as métricas (padrão)")
    print("  Ou especifique métricas individuais: SADDR DADDR SPORT DPORT CWND SRTT")
    print("  RTTVAR RET SNDWND RCVWND DSCP ECN ALG TIMESTAMP")
    print("\nExemplos:")
    print("  python3 monitor.py -last -all")
    print("  python3 monitor.py -seg SADDR DADDR SPORT DPORT")
    print("  python3 monitor.py --simple CWND SRTT RTTVAR")
    print("  python3 monitor.py SADDR DADDR")

def parse_arguments():
    """
    Parse os argumentos da linha de comando
    Retorna: (modo, lista_de_metricas)
    """
    if len(sys.argv) == 1:
        return "-last", ["all"]
    
    # Modos disponíveis
    modes = ["-last", "-seg", "--simple"]
    
    # Encontra o modo
    selected_mode = "-last"  # padrão
    metrics_start_index = 1
    
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg in modes:
            selected_mode = arg
            metrics_start_index = i + 1
            break
    
    # Coleta as métricas
    selected_metrics = []
    for arg in sys.argv[metrics_start_index:]:
        if arg.upper() in ALL_METRICS or arg == "-all":
            if arg == "-all":
                selected_metrics = ["all"]
                break
            else:
                selected_metrics.append(arg.upper())
    
    # Se nenhuma métrica foi especificada, usa "all"
    if not selected_metrics:
        selected_metrics = ["all"]
    
    return selected_mode, selected_metrics

if __name__ == "__main__":
    # Parse dos argumentos
    mode, metrics = parse_arguments()
    
    # Executa no modo selecionado com as métricas escolhidas
    if mode == "-last":
        display_metrics(metrics)
    elif mode == "-seg":
        display_metrics_sequential(metrics)
    elif mode == "--simple":
        display_metrics_simple(metrics)
    else:
        print(f"Modo desconhecido: {mode}")
        show_usage()