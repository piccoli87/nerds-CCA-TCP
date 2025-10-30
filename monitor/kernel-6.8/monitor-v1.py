#!/usr/bin/env python3
import subprocess
import time
import sys
import os

def get_tcp_metrics():
    """
    Executa o comando para obter as métricas TCP e retorna a saída
    """
    try:
        # Executa o comando e captura a saída
        result = subprocess.run(
            ['cat', '/proc/tcp_metrics'],  # Corrigido: é /proc/tcp_metrics
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

def display_metrics():
    """
    Exibe as métricas TCP a cada segundo (com limpeza de tela)
    """
    try:
        while True:
            # Limpa a tela
            os.system('clear' if os.name == 'posix' else 'cls')
            
            # Obtém as métricas atuais
            metrics = get_tcp_metrics()
            
            # Exibe com timestamp
            print(f"=== Métricas TCP - {time.strftime('%H:%M:%S')} ===")
            print(metrics)
            print("=" * 50)
            print("Pressione Ctrl+C para sair...")
            
            # Aguarda 1 segundo
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\nMonitoramento encerrado.")
    except Exception as e:
        print(f"Erro durante o monitoramento: {e}")

def display_metrics_simple():
    """
    Versão alternativa que não limpa a tela, apenas adiciona novas linhas
    """
    try:
        print("Iniciando monitoramento de métricas TCP...")
        print("Pressione Ctrl+C para sair\n")
        
        while True:
            metrics = get_tcp_metrics()
            
            print(f"\n--- Métricas TCP - {time.strftime('%H:%M:%S')} ---")
            print(metrics)
            print("-" * 40)
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado.")

def display_metrics_sequential():
    """
    Versão que imprime todas as capturas sequencialmente sem limpar tela
    """
    try:
        print("Iniciando monitoramento sequencial de métricas TCP...")
        print("Todas as capturas serão exibidas sequencialmente")
        print("Pressione Ctrl+C para sair\n")
        
        capture_count = 0
        
        while True:
            metrics = get_tcp_metrics()
            capture_count += 1
            
            print(f"\n--- Captura #{capture_count} - {time.strftime('%H:%M:%S')} ---")
            print(metrics)
            print("-" * 50)
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\nMonitoramento encerrado. Total de {capture_count} capturas realizadas.")

def show_usage():
    """
    Exibe o uso correto do script
    """
    print("Uso: python3 monitor.py [OPÇÃO]")
    print("\nOpções:")
    print("  -last     : Exibe apenas a última captura (limpa tela a cada atualização)")
    print("  -seg      : Exibe todas as capturas sequencialmente")
    print("  --simple  : Modo simples sem limpar tela")
    print("  sem parâmetro: Usa o modo padrão (-last)")

if __name__ == "__main__":
    # Verifica os argumentos passados
    if len(sys.argv) > 1:
        if sys.argv[1] == "-last":
            display_metrics()
        elif sys.argv[1] == "-seg":
            display_metrics_sequential()
        elif sys.argv[1] == "--simple":
            display_metrics_simple()
        else:
            print(f"Parâmetro desconhecido: {sys.argv[1]}")
            show_usage()
    else:
        # Comportamento padrão (equivalente a -last)
        display_metrics()