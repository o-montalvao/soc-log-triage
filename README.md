# soc-log-triage

[![testes](https://github.com/o-montalvao/soc-log-triage/actions/workflows/tests.yml/badge.svg)](https://github.com/o-montalvao/soc-log-triage/actions/workflows/tests.yml)

Ferramenta de linha de comando que lê um log de acesso de servidor web (formato *combined*, usado pelo Nginx e pelo Apache) e aponta padrões que um analista de SOC investigaria: muitas tentativas de login falhas vindas do mesmo IP (possível força bruta) e muitas respostas 404 do mesmo IP (possível varredura de diretórios).

Projeto de estudo, feito para praticar triagem de logs (análise de registros para identificar incidentes) e testes automatizados com Python.

## Como funciona

Cada linha do log é separada em campos (IP, caminho, status HTTP) por uma expressão regular, que é um padrão de texto usado para reconhecer o formato da linha. Linhas que não seguem o formato são ignoradas, sem interromper a análise. Depois, o script conta eventos por IP e compara com dois limites:

- 5 ou mais falhas de login (status 401 ou 403 em `/login`): severidade ALTA
- 10 ou mais respostas 404: severidade MÉDIA

## Exemplo de saída

Com o log de exemplo incluído no repositório:

```
# Relatório de triagem de logs

Arquivo analisado: `sample/access.log`

- **[ALTA]** `192.0.2.66`: 5 tentativas de login falhas em /login (possível força bruta)
- **[MÉDIA]** `192.0.2.77`: 14 respostas 404 (possível varredura de diretórios)
```

## Como rodar

Requisito: Python 3.10 ou superior.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pytest
python detect.py sample/access.log
pytest -v
```

## Estrutura

- `detect.py`: script principal, com a leitura do log e as regras
- `tests/test_detect.py`: testes automatizados
- `sample/access.log`: log de exemplo
- `.github/workflows/tests.yml`: pipeline de CI, que roda os testes a cada push

## Limitações

- O `sample/access.log` foi escrito à mão para teste. Não é tráfego real.
- Os limites (5 e 10) foram escolhidos por intuição, não medidos em um servidor real.
- A regra não considera janela de tempo: cinco falhas espalhadas ao longo de um dia contam o mesmo que cinco em um segundo.
- O teste de força bruta usa seis linhas com limite de cinco. Se o limite mudar para seis, o teste continua passando, então ele não protege totalmente a regra.
- Não há leitura de logs compactados nem análise em tempo real.

## Próximos passos

- Janela de tempo por IP
- Saída em JSON
- Empacotamento com Docker
- Explicação dos achados com IA, a partir de um modelo local ou de API
