"""Aula 07 | Relatório técnico didático de triagem de IPs e MACs.

Requisitos: pip install reportlab
Uso autônomo: python relatorio_aula07.py
Uso com JSON: python relatorio_aula07.py --dados entradas.json --saida ./meus_relatorios

Este programa NÃO valida autoria, invasão, legitimidade ou cadeia de custódia
judicial; os dados-exemplo são didáticos e se originam do notebook enviado.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)

VERSAO = "2.0"
IP_ALVO_PADRAO = "192.168.0.99"
EXEMPLO_IPS = ["10.0.0.5", "172.16.0.3", "192.168.0.99", "192.168.1.10", "10.10.0.22"]
EXEMPLO_MACS = ["00:1A:2B", "FF:EE:DD", "12:34:56", "AA:BB:CC:DD:EE:FF"]
REDES_PRIVADAS_IPV4 = tuple(ipaddress.ip_network(s) for s in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def agora_brasilia() -> datetime:
    return datetime.now(ZoneInfo("America/Sao_Paulo"))


def texto(valor, limite=500) -> str:
    """Conserva o dado de entrada como texto para análise e relatório."""
    if valor is None:
        return ""
    return str(valor).strip()[:limite]


def classificar_ip(endereco: ipaddress._BaseAddress) -> str:
    if endereco.version == 4 and any(endereco in rede for rede in REDES_PRIVADAS_IPV4):
        return "Privado (RFC 1918)"
    if endereco.is_loopback:
        return "Loopback"
    if endereco.is_link_local:
        return "Link-local"
    if endereco.is_multicast:
        return "Multicast"
    if endereco.is_reserved:
        return "Reservado"
    if endereco.is_global:
        return "Global"
    return "Não global/outro"


def analisar_ips(ips, alvo: str):
    registros = []
    normalizados = []
    try:
        alvo_normalizado = str(ipaddress.ip_address(texto(alvo)))
    except ValueError as exc:
        raise ValueError(f"IP alvo inválido: {alvo!r}") from exc

    for indice, bruto in enumerate(ips, 1):
        original = texto(bruto)
        reg = {"ordem": indice, "informado": original, "normalizado": "", "valido": False,
               "classe": "Não determinado", "alvo": False, "observacao": ""}
        try:
            addr = ipaddress.ip_address(original)
        except ValueError:
            reg["observacao"] = "Não representa um endereço IPv4/IPv6 válido"
        else:
            reg.update(normalizado=str(addr), valido=True, classe=classificar_ip(addr),
                       alvo=(str(addr) == alvo_normalizado))
            normalizados.append(str(addr))
        registros.append(reg)
    contagens = Counter(normalizados)
    for r in registros:
        if r["valido"] and contagens[r["normalizado"]] > 1:
            r["observacao"] = f"Repetido na lista ({contagens[r['normalizado']]} ocorrências)"
        elif r["valido"]:
            r["observacao"] = "Registro textual validado; evento não verificado"
    return registros, alvo_normalizado


def normalizar_mac(valor: str):
    s = texto(valor).upper()
    if re.fullmatch(r"[0-9A-F]{12}", s):
        hexa = s
    elif re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", s):
        hexa = s.replace(":", "")
    elif re.fullmatch(r"(?:[0-9A-F]{2}-){5}[0-9A-F]{2}", s):
        hexa = s.replace("-", "")
    elif re.fullmatch(r"(?:[0-9A-F]{4}\.){2}[0-9A-F]{4}", s):
        hexa = s.replace(".", "")
    else:
        return "", "Formato incompleto ou inválido; esperado 12 dígitos hexadecimais (6 octetos)"
    return ":".join(hexa[i:i + 2] for i in range(0, 12, 2)), ""


def analisar_macs(macs):
    registros = []
    normalizados = []
    for indice, bruto in enumerate(macs, 1):
        original = texto(bruto)
        normalizado, motivo = normalizar_mac(original)
        if normalizado:
            normalizados.append(normalizado)
        registros.append({"ordem": indice, "informado": original,
                          "normalizado": normalizado, "valido": bool(normalizado),
                          "observacao": motivo})
    contagens = Counter(normalizados)
    for r in registros:
        if r["valido"]:
            n = contagens[r["normalizado"]]
            r["observacao"] = f"Repetido na lista ({n} ocorrências)" if n > 1 else "Sintaxe de 48 bits válida; origem não verificada"
    return registros


def analisar(config, ips, macs):
    if not isinstance(ips, (list, tuple)) or not isinstance(macs, (list, tuple)):
        raise TypeError("Os registros de IP e MAC precisam ser listas ou tuplas.")
    ip_regs, alvo = analisar_ips(ips, config.get("ip_alvo", IP_ALVO_PADRAO))
    mac_regs = analisar_macs(macs)
    ips_validos = [r for r in ip_regs if r["valido"]]
    macs_validos = [r for r in mac_regs if r["valido"]]
    resumo = {
        "ips_recebidos": len(ip_regs),
        "ips_validos": len(ips_validos),
        "ips_invalidos": len(ip_regs) - len(ips_validos),
        "ips_distintos_validos": len({r["normalizado"] for r in ips_validos}),
        "macs_recebidos": len(mac_regs),
        "macs_validos": len(macs_validos),
        "macs_invalidos_ou_incompletos": len(mac_regs) - len(macs_validos),
        "macs_distintos_validos": len({r["normalizado"] for r in macs_validos}),
        "alvo_registros": sum(r["alvo"] for r in ip_regs),
        "alvo_presente": any(r["alvo"] for r in ip_regs),
    }
    return {"ip_alvo_normalizado": alvo, "registros_ip": ip_regs,
            "registros_mac": mac_regs, "resumo": resumo}


def hash_json_canonico(dados):
    return hashlib.sha256(json.dumps(dados, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def hash_arquivo(caminho: Path):
    d = hashlib.sha256()
    with caminho.open("rb") as arq:
        for bloco in iter(lambda: arq.read(1024 * 1024), b""):
            d.update(bloco)
    return d.hexdigest()


def obter_fonte(nome):
    font_paths = [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf", "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf"),
    ]
    for regular, bold in font_paths:
        if Path(regular).exists() and Path(bold).exists():
            if "AulaRegular" not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont("AulaRegular", regular))
                pdfmetrics.registerFont(TTFont("AulaBold", bold))
                pdfmetrics.registerFontFamily("AulaRegular", normal="AulaRegular", bold="AulaBold")
            return "AulaRegular", "AulaBold"
    return "Helvetica", "Helvetica-Bold"


def adicionar_pdf(caminho: Path, config: dict, analise: dict, hash_entradas: str, data_geracao: str):
    nome_fonte, fonte_negrito = obter_fonte("preferencial")
    AZUL = colors.HexColor("#18344F")
    CINZA = colors.HexColor("#546578")
    FUNDO = colors.HexColor("#F3F6F9")
    LINHA = colors.HexColor("#DEE6EC")
    VERDE = colors.HexColor("#226B50")
    VERMELHO = colors.HexColor("#99473D")
    margem = 38
    largura_util = A4[0] - 2 * margem
    folha = BaseDocTemplate(str(caminho), pagesize=A4, leftMargin=margem, rightMargin=margem,
                            topMargin=66, bottomMargin=56, title="Relatório técnico didático - Aula 07",
                            author="Gerador didático Aula 07", subject="Análise descritiva de IPs e MACs")

    styles = {
        "titulo": ParagraphStyle("titulo07", fontName=fonte_negrito, fontSize=19, leading=25, textColor=AZUL, spaceAfter=9),
        "sub": ParagraphStyle("sub07", fontName=fonte_negrito, fontSize=11.2, leading=16, textColor=AZUL, spaceBefore=11, spaceAfter=5, keepWithNext=True),
        "normal": ParagraphStyle("normal07", fontName=nome_fonte, fontSize=8.5, leading=12.3, spaceAfter=4),
        "mini": ParagraphStyle("mini07", fontName=nome_fonte, fontSize=7.3, leading=10.2, spaceAfter=1),
        "mini_bold": ParagraphStyle("miniB07", fontName=fonte_negrito, fontSize=7.4, leading=10.5, textColor=colors.white),
        "etiqueta": ParagraphStyle("etag07", fontName=fonte_negrito, fontSize=8.5, leading=12, textColor=VERDE, spaceAfter=12),
        "muted": ParagraphStyle("muted07", fontName=nome_fonte, fontSize=8, leading=11.5, textColor=CINZA, spaceAfter=6),
        "hash": ParagraphStyle("hash07", fontName=nome_fonte, fontSize=7.2, leading=10.5, wordWrap="CJK", textColor=AZUL),
    }

    def p(valor, tipo="normal"):
        return Paragraph(escape(texto(valor, limite=4000)).replace("\n", "<br/>"), styles[tipo])

    def titulo(secao):
        blocos.append(p(secao, "sub"))

    def tabela(linhas, larguras, cabecalho=True):
        dados = []
        for linha_idx, linha in enumerate(linhas):
            estilo = "mini_bold" if cabecalho and linha_idx == 0 else "mini"
            dados.append([p(str(x), estilo) for x in linha])
        t = Table(dados, colWidths=larguras, repeatRows=1 if cabecalho else 0, hAlign="LEFT")
        comandos = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, -1), (-1, -1), 0.45, LINHA),
        ]
        if cabecalho:
            comandos.extend([("BACKGROUND", (0, 0), (-1, 0), AZUL),
                             ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, FUNDO]),
                             ("LINEBELOW", (0, 0), (-1, 0), 0.5, AZUL)])
        t.setStyle(TableStyle(comandos))
        blocos.append(t)
        blocos.append(Spacer(1, 6))

    def numero_pagina(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setStrokeColor(LINHA)
        canvas.line(margem, h - 44, w - margem, h - 44)
        canvas.setFont(fonte_negrito, 8)
        canvas.setFillColor(AZUL)
        canvas.drawString(margem, h - 33, "PMGO / SENAC  |  AULA 07  |  TRIAGEM DIDÁTICA")
        canvas.setFont(nome_fonte, 7.3)
        canvas.setFillColor(CINZA)
        canvas.line(margem, 42, w - margem, 42)
        canvas.drawString(margem, 29, "Simulação acadêmica. Não constitui laudo pericial nem comprovação de crime.")
        canvas.drawRightString(w - margem, 29, f"Página {doc.page}")
        canvas.restoreState()

    frame = Frame(margem, 56, largura_util, A4[1] - 56 - 66, leftPadding=0, rightPadding=0,
                  topPadding=0, bottomPadding=0)
    folha.addPageTemplates([PageTemplate(id="Relatorio", frames=[frame], onPage=numero_pagina)])
    blocos = []
    resumo = analise["resumo"]
    alvo = analise["ip_alvo_normalizado"]

    blocos.append(p("RELATÓRIO TÉCNICO DE TRIAGEM DIGITAL", "titulo"))
    blocos.append(p("SIMULAÇÃO ACADÊMICA  |  DADOS DO NOTEBOOK AULA 07", "etiqueta"))
    blocos.append(p("Objeto: inventário e validação de endereços IP e MAC informados em um exercício de Python. Não foram analisados arquivos originais de logs, pacotes de rede ou equipamentos.", "normal"))

    titulo("1. Identificação, contexto e proveniência")
    ident = [
        ("Identificador", config.get("identificador") or "Não informado"),
        ("Responsável indicado", config.get("analista") or "Não informado"),
        ("Unidade / turma", config.get("unidade") or "Não informado"),
        ("Origem declarada", config.get("origem") or "Não informada"),
        ("Data/hora de geração (America/Sao_Paulo)", data_geracao),
        ("Data/hora de coleta dos registros", config.get("data_coleta") or "Não informada"),
        ("Natureza", "Exercício didático; não são vestígios autenticados"),
        ("IP de interesse", alvo),
    ]
    tabela([["Campo", "Informação"]] + ident, [190, largura_util - 190])

    titulo("2. Sumário executivo")
    sumario = [
        ["Indicador", "Resultado", "Interpretação"],
        ["IPs informados", str(resumo["ips_recebidos"]), "Total de linhas na lista, não de conexões"],
        ["IPs válidos", str(resumo["ips_validos"]), "Validação sintática de endereços"],
        ["IPs inválidos", str(resumo["ips_invalidos"]), "Não puderam ser interpretados como endereço IP"],
        ["MACs informados", str(resumo["macs_recebidos"]), "Total de textos registrados, não de dispositivos comprovados"],
        ["MACs completos/válidos", str(resumo["macs_validos"]), "Formato de 48 bits, não autenticação do dispositivo"],
        ["MACs incompletos/inválidos", str(resumo["macs_invalidos_ou_incompletos"]), "Precisam de correção na fonte"],
        ["Ocorrências do IP alvo", str(resumo["alvo_registros"]), "Apenas igualdade de texto/IP normalizado"],
    ]
    tabela(sumario, [150, 63, largura_util - 213])
    achado = (f"O IP {alvo} CONSTA em {resumo['alvo_registros']} registro(s) da lista didática."
              if resumo["alvo_presente"] else
              f"O IP {alvo} NÃO CONSTA entre os registros IP válidos informados.")
    blocos.append(p("Resultado objetivo: " + achado))
    blocos.append(p("Classificação de ameaça, autoria, invasão, conexão efetiva, origem dos dispositivos e número de pessoas envolvidas: NÃO DETERMINADOS pelos dados recebidos.", "muted"))

    titulo("3. Método aplicado")
    for passo in [
        "Entrada: listas informadas no notebook; não houve coleta direta da rede.",
        "Validação de IPs com a biblioteca padrão ipaddress; classificação de endereços privados IPv4 conforme RFC 1918.",
        "Validação de formato MAC com 12 dígitos hexadecimais; endereços abreviados são marcados como incompletos.",
        "Conferência de duplicidades e correspondência exata com o IP de interesse.",
        "Preservação de uma fotografia serializada das entradas e resultados em JSON; cálculo de SHA-256 desse JSON canônico.",
    ]:
        blocos.append(p("• " + passo, "mini"))

    titulo("4. Registros IP e verificações")
    ip_linhas = [["#", "Endereço informado", "Status", "Classificação", "Alvo?", "Observação"]]
    for r in analise["registros_ip"]:
        ip_linhas.append([r["ordem"], r["informado"] or "(vazio)", "Válido" if r["valido"] else "Inválido",
                          r["classe"], "Sim" if r["alvo"] else "Não", r["observacao"]])
    if len(ip_linhas) == 1:
        ip_linhas.append(["-", "Sem dados", "-", "-", "-", "Nenhum IP fornecido"])
    tabela(ip_linhas, [22, 92, 46, 106, 38, largura_util - 304])

    titulo("5. Registros MAC e verificações")
    mac_linhas = [["#", "Valor informado", "Normalizado", "Status", "Observação"]]
    for r in analise["registros_mac"]:
        mac_linhas.append([r["ordem"], r["informado"] or "(vazio)", r["normalizado"] or "Não aplicável",
                           "Válido" if r["valido"] else "Inválido", r["observacao"]])
    if len(mac_linhas) == 1:
        mac_linhas.append(["-", "Sem dados", "-", "-", "Nenhum MAC fornecido"])
    tabela(mac_linhas, [22, 99, 117, 48, largura_util - 286])

    titulo("6. Integridade, rastreabilidade e cadeia de custódia")
    blocos.append(p("SHA-256 da representação JSON canônica das ENTRADAS E RESULTADOS deste relatório:", "normal"))
    blocos.append(p(hash_entradas, "hash"))
    blocos.append(Spacer(1, 7))
    blocos.append(p("Este hash verifica os dados serializados que alimentaram o relatório; não é hash de arquivo de log original nem prova de autenticidade de coleta. O hash do arquivo PDF é calculado depois da geração e salvo separadamente no arquivo SHA256SUMS.txt.", "mini"))
    eventos = config.get("movimentacoes_custodia") or []
    if eventos:
        mov = [["Data/hora informada", "Responsável", "Ato / movimentação"]]
        for e in eventos:
            mov.append([texto(e.get("data_hora"), 80) or "Não informado",
                        texto(e.get("responsavel"), 100) or "Não informado",
                        texto(e.get("ato"), 300) or "Não informado"])
        tabela(mov, [125, 130, largura_util - 255])
        blocos.append(p("Os eventos de custódia acima foram declarados pelo usuário, sem verificação documental pelo programa.", "mini"))
    else:
        blocos.append(p("Movimentações de cadeia de custódia: nenhuma informada ou documentalmente verificada.", "normal"))
    blocos.append(p("Campos ainda não comprovados: aquisição de log original, equipamento de origem, data/hora do evento, responsável pela coleta, método de extração, cadeia de transferência e assinatura digital.", "muted"))

    titulo("7. Limitações e cuidados de interpretação")
    for limite in [
        "A presença de um IP na lista não demonstra tentativa de ataque, acesso indevido, autoria ou conexão efetiva.",
        "Endereços IP privados podem ser reutilizados em redes diferentes e não identificam uma pessoa.",
        "MACs abreviados nos slides não são endereços completos de 48 bits; a contagem de linhas não equivale a número de dispositivos identificados.",
        "Uma tupla Python restringe alteração direta de elementos, mas NÃO implementa sozinha cadeia de custódia ou armazenamento inviolável.",
        "Este PDF não recebeu assinatura digital; a validação de dados é sintática, e não pericial.",
    ]:
        blocos.append(p("• " + limite, "mini"))

    titulo("8. Conclusão e encaminhamentos")
    blocos.append(p(achado))
    blocos.append(p(f"Foram processados {resumo['ips_recebidos']} registros de IP ({resumo['ips_validos']} com sintaxe válida) e {resumo['macs_recebidos']} registros MAC ({resumo['macs_validos']} completos). Os resultados estão limitados ao conjunto informado."))
    blocos.append(p("Encaminhamento didático: revisar MACs incompletos com a fonte; conservar arquivo JSON e checksums; documentar origem, datas e responsáveis se futuramente houver evidências reais."))
    if config.get("observacoes"):
        titulo("Observações fornecidas")
        blocos.append(p(config["observacoes"]))

    blocos.append(p("Documento gerado automaticamente; o pacote de exportação inclui PDF, JSON e checksums separados. Revise os dados antes de qualquer uso fora do laboratório.", "muted"))
    folha.build(blocos)
    return caminho


def gerar_relatorio_aula07(config: dict, ips, macs, pasta="relatorios_aula07"):
    """Cria PDF + JSON + checksum TXT; retorna caminhos e resumo sem alterar entradas."""
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    data = agora_brasilia()
    hora_local = data.isoformat(timespec="seconds")
    carimbo = data.strftime("%Y%m%d_%H%M%S_%f")
    identificador = re.sub(r"[^A-Za-z0-9_-]", "_", texto(config.get("identificador") or "AULA07", 64))
    base = f"Aula07_Relatorio_{identificador}_{carimbo}"
    pdf_path = pasta / (base + ".pdf")
    json_path = pasta / (base + ".json")
    sha_path = pasta / (base + "_SHA256SUMS.txt")
    ips = list(ips)
    macs = list(macs)
    analise = analisar(config, ips, macs)
    conteudo = {
        "gerador_versao": VERSAO,
        "gerado_em_america_sao_paulo": hora_local,
        "metadados_declarados": config,
        "dados_de_entrada": {"ips": ips, "macs": macs},
        "analise": analise,
        "nota": "Dados do exercício; hash não comprova integridade de evidência externa nem cadeia de custódia.",
    }
    digest = hash_json_canonico(conteudo)
    manifesto = {"sha256_conteudo_canonico": digest, "conteudo": conteudo}
    json_path.write_text(json.dumps(manifesto, ensure_ascii=False, indent=2), encoding="utf-8")
    adicionar_pdf(pdf_path, config, analise, digest, hora_local)
    sha_path.write_text(
        f"{hash_arquivo(pdf_path)}  {pdf_path.name}\n"
        f"{hash_arquivo(json_path)}  {json_path.name}\n",
        encoding="utf-8",
    )
    return {"pdf": pdf_path, "json": json_path, "sha256": sha_path,
            "resumo": analise["resumo"], "digest_conteudo": digest}


CONFIG_EXEMPLO = {
    "identificador": "AULA07-LAB",
    "analista": "",   # Preencher somente com informação verdadeira
    "unidade": "PMGO / SENAC - Aula 07 (atividade didática)",
    "origem": "Listas demonstrativas do notebook Aula_07_Cadeia_de_Custodia_PMGO.ipynb",
    "data_coleta": "",  # Não atribuir a data da geração como se fosse data da coleta
    "ip_alvo": IP_ALVO_PADRAO,
    "observacoes": "Entradas didáticas. Não há arquivos de logs brutos fornecidos.",
    "movimentacoes_custodia": [],
}


def _cli():
    parser = argparse.ArgumentParser(description="Gera relatório técnico didático da Aula 07 em PDF.")
    parser.add_argument("--dados", type=Path, help="JSON contendo chaves config, ips, macs. Sem esta opção usa exemplos do notebook.")
    parser.add_argument("--saida", type=Path, default=Path("relatorios_aula07"), help="Pasta de saída")
    args = parser.parse_args()
    if args.dados:
        entrada = json.loads(args.dados.read_text(encoding="utf-8"))
        config, ips, macs = entrada.get("config", CONFIG_EXEMPLO), entrada["ips"], entrada["macs"]
    else:
        config, ips, macs = CONFIG_EXEMPLO, EXEMPLO_IPS, EXEMPLO_MACS
    arquivos = gerar_relatorio_aula07(config, ips, macs, args.saida)
    print("Arquivos gerados:")
    for chave in ("pdf", "json", "sha256"):
        print(f"  {chave}: {arquivos[chave]}")
    print("Resumo:", json.dumps(arquivos["resumo"], ensure_ascii=False))

if __name__ == "__main__":
    _cli()
