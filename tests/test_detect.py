from detect import analyze, parse_line

LINHA_401 = '192.0.2.10 - - [12/Nov/2026:10:00:00 +0000] "POST /login HTTP/1.1" 401 153 "-" "curl/8.0"'


def test_parse_line_extrai_ip_e_status():
    entry = parse_line(LINHA_401)
    assert entry["ip"] == "192.0.2.10"
    assert entry["status"] == "401"
    assert entry["path"] == "/login"


def test_linha_malformada_retorna_none():
    assert parse_line("isto não é um log") is None


def test_detecta_forca_bruta_acima_do_limite():
    linhas = [LINHA_401.replace("192.0.2.10", "192.0.2.66")] * 6
    achados = analyze(linhas)
    assert any(sev == "ALTA" and ip == "192.0.2.66" for sev, ip, _ in achados)


def test_ip_normal_nao_gera_alerta():
    linha_ok = '192.0.2.5 - - [12/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    assert analyze([linha_ok] * 50) == []
