import re
import sys
from collections import Counter
from pathlib import Path

# Expressão regular para o formato "combined" do Nginx/Apache:
# IP - - [data] "MÉTODO caminho PROTOCOLO" status ...
LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d{3})'
)

# Limites escolhidos por intuição, não por medição em tráfego real.
LOGIN_FAIL_LIMIT = 5   # falhas de login por IP
NOT_FOUND_LIMIT = 10   # respostas 404 por IP


def parse_line(line):
    """Devolve um dicionário com os campos da linha, ou None se não bater com o formato."""
    match = LINE_RE.match(line)
    return match.groupdict() if match else None


def analyze(lines):
    """Conta eventos por IP e devolve uma lista de achados (severidade, IP, descrição)."""
    failed_logins = Counter()
    not_found = Counter()

    for line in lines:
        entry = parse_line(line)
        if entry is None:
            continue  # ignora linhas fora do formato, em vez de quebrar
        ip, path, status = entry["ip"], entry["path"], entry["status"]

        if path.startswith("/login") and status in ("401", "403"):
            failed_logins[ip] += 1
        if status == "404":
            not_found[ip] += 1

    findings = []
    for ip, count in failed_logins.items():
        if count >= LOGIN_FAIL_LIMIT:
            findings.append(("ALTA", ip, f"{count} tentativas de login falhas em /login (possível força bruta)"))
    for ip, count in not_found.items():
        if count >= NOT_FOUND_LIMIT:
            findings.append(("MÉDIA", ip, f"{count} respostas 404 (possível varredura de diretórios)"))
    return findings


def main():
    if len(sys.argv) != 2:
        print("uso: python detect.py <arquivo_de_log>")
        sys.exit(1)

    log_file = Path(sys.argv[1])
    findings = analyze(log_file.read_text(encoding="utf-8").splitlines())

    print("# Relatório de triagem de logs\n")
    print(f"Arquivo analisado: `{log_file}`\n")
    if not findings:
        print("Nenhum achado acima dos limites configurados.")
    for severity, ip, description in findings:
        print(f"- **[{severity}]** `{ip}`: {description}")


if __name__ == "__main__":
    main()