"""Aula 07 - Painel visual didatico de triagem de IPs/MACs.

Colab: veja o notebook Aula07_App_Visual_Colab.ipynb.
Windows: python -m pip install -r requirements.txt && python app.py
Nao realiza captura de rede, atribuicao de autoria ou analise forense de logs brutos.
"""
from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
import re
import tempfile
from zipfile import ZipFile, ZIP_DEFLATED

import gradio as gr
from Relatorio_Aula07_Gerador import (
    EXEMPLO_IPS,
    EXEMPLO_MACS,
    IP_ALVO_PADRAO,
    analisar,
    gerar_relatorio_aula07,
)

MAX_REGISTROS = 500
MAX_CARACTERES = 50000
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
FORMATS = {".txt", ".csv", ".json"}

CSS = """
.gradio-container {max-width: 1240px !important; margin: auto !important;}
#hero {border:1px solid #d7e3ec; border-radius:18px; padding:22px 24px;
background:linear-gradient(110deg,#112d47 0%,#1c4865 100%);color:white;}
#hero h1 {color:white; margin:0 0 6px 0;font-size:2rem;}
#hero p {color:#d8e7f0; font-size:0.95rem; margin:0;}
.kpi-grid {display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:8px 0 12px;}
.kpi {padding:14px;border-radius:12px;background:var(--block-background-fill,#f2f6f9);
border:1px solid var(--border-color-primary,#d7e2ec);min-height:108px;}
.kpi .label {font-size:.78rem;opacity:.78;line-height:1.3;}
.kpi .number {font-size:1.8rem;font-weight:750;margin-top:5px;}
.kpi .note {font-size:.75rem;opacity:.8;}
.tag {display:inline-block; border:1px solid currentColor;padding:3px 9px;border-radius:999px;font-size:.8rem;}
@media(max-width:720px){.kpi-grid {grid-template-columns:repeat(2,minmax(0,1fr));}}
"""


def ler_linhas(campo: str, nome: str) -> list[str]:
    """Aceita um registro por linha ou itens separados por ; / , ."""
    bruto = str(campo or "")
    if len(bruto) > MAX_CARACTERES:
        raise ValueError(f"{nome}: texto excede {MAX_CARACTERES} caracteres.")
    valores = [s.strip() for s in re.split(r"[\n\r;,]+", bruto) if s.strip()]
    if len(valores) > MAX_REGISTROS:
        raise ValueError(f"{nome}: limite de {MAX_REGISTROS} registros por análise.")
    return valores


def preparar(ips_texto: str, macs_texto: str, ip_alvo: str):
    ips = ler_linhas(ips_texto, "IPs")
    macs = ler_linhas(macs_texto, "MACs")
    if not ips and not macs:
        raise ValueError("Informe pelo menos um IP ou um MAC para analisar.")
    return ips, macs, analisar({"ip_alvo": (ip_alvo or "").strip()}, ips, macs)


def metricas_html(resumo: dict) -> str:
    cards = [
        ("IPs informados", str(resumo["ips_recebidos"]), f'{resumo["ips_validos"]} com formato válido'),
        ("MACs informados", str(resumo["macs_recebidos"]), f'{resumo["macs_invalidos_ou_incompletos"]} incompleto(s)/inválido(s)'),
        ("Ocorrências do IP alvo", str(resumo["alvo_registros"]), "Registros, não conexões comprovadas"),
        ("IPs distintos válidos", str(resumo["ips_distintos_validos"]), "Depois da normalização"),
    ]
    return '<div class="kpi-grid">' + "".join(
        f'<div class="kpi"><div class="label">{html.escape(a)}</div>'
        f'<div class="number">{html.escape(b)}</div><div class="note">{html.escape(c)}</div></div>'
        for a, b, c in cards
    ) + "</div>"


def tabelas(resultado: dict):
    ip_rows = [[r["ordem"], r["informado"], r["normalizado"] or "—",
                "Válido" if r["valido"] else "Inválido", r["classe"],
                "Sim" if r["alvo"] else "Não", r["observacao"]]
               for r in resultado["registros_ip"]]
    mac_rows = [[r["ordem"], r["informado"], r["normalizado"] or "—",
                 "Válido" if r["valido"] else "Incompleto / inválido", r["observacao"]]
                for r in resultado["registros_mac"]]
    return ip_rows, mac_rows


def analisar_entrada(ips_texto: str, macs_texto: str, ip_alvo: str):
    try:
        _ips, _macs, resultado = preparar(ips_texto, macs_texto, ip_alvo)
        r = resultado["resumo"]
        alvo = resultado["ip_alvo_normalizado"]
        situacao = f"**IP {alvo}: encontrado em {r['alvo_registros']} registro(s).**" if r["alvo_presente"] else f"**IP {alvo}: não encontrado.**"
        alerta = f"\n\n**Atenção:** {r['macs_invalidos_ou_incompletos']} MAC(s) incompleto(s) ou inválido(s)." if r["macs_invalidos_ou_incompletos"] else ""
        mensagem = (
            situacao + f"\n\nIPs válidos: **{r['ips_validos']}/{r['ips_recebidos']}**. "
            f"MACs completos: **{r['macs_validos']}/{r['macs_recebidos']}**." + alerta +
            "\n\n*Análise sintática de registros informados; não é detecção de intrusão nem validação de autoria.*"
        )
        return metricas_html(r), mensagem, *tabelas(resultado)
    except (ValueError, TypeError) as exc:
        return "", f"**Erro de validação:** {exc}", [], []


def gerar_arquivos(ips_texto: str, macs_texto: str, ip_alvo: str,
                   identificador: str, analista: str, unidade: str,
                   origem: str, data_coleta: str, observacoes: str):
    try:
        ips, macs, _ = preparar(ips_texto, macs_texto, ip_alvo)
        identificador = (identificador or "AULA07-LAB").strip()[:64]
        config = {
            "identificador": identificador,
            "analista": (analista or "").strip()[:200],
            "unidade": (unidade or "").strip()[:300],
            "origem": (origem or "").strip()[:500],
            "data_coleta": (data_coleta or "").strip()[:100],
            "ip_alvo": (ip_alvo or "").strip(),
            "observacoes": (observacoes or "").strip()[:2500],
            "movimentacoes_custodia": [],
        }
        pasta = Path(tempfile.mkdtemp(prefix="aula07_painel_"))
        arquivos = gerar_relatorio_aula07(config, ips, macs, pasta=pasta)
        pacote = pasta / f"{Path(arquivos['pdf']).stem}_PACOTE.zip"
        with ZipFile(pacote, "w", compression=ZIP_DEFLATED) as zipfile:
            for key in ("pdf", "json", "sha256"):
                p = Path(arquivos[key])
                zipfile.write(p, arcname=p.name)
        resumo = arquivos["resumo"]
        return (str(arquivos["pdf"]), str(arquivos["json"]),
                str(arquivos["sha256"]), str(pacote),
                f"Arquivos gerados com sucesso. **{resumo['ips_validos']} IPs válidos**, "
                f"**{resumo['macs_validos']} MAC(s) completo(s)**. "
                "Baixe o ZIP e guarde o PDF e o manifesto juntos.")
    except (ValueError, TypeError, OSError) as exc:
        return None, None, None, None, f"**Falha na geração:** {exc}"


def _arquivo_texto_seguro(caminho: str) -> str:
    arquivo = Path(caminho)
    if arquivo.suffix.lower() not in FORMATS:
        raise ValueError("Formato não permitido. Use TXT, CSV ou JSON.")
    if arquivo.stat().st_size > MAX_UPLOAD_BYTES:
        raise ValueError("Arquivo ultrapassa o limite de 2 MB.")
    try:
        return arquivo.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as e:
        raise ValueError("Arquivo deve utilizar codificação UTF-8.") from e


def _ler_registros(caminho: str, tipo: str) -> list[str]:
    conteudo = _arquivo_texto_seguro(caminho)
    extensao = Path(caminho).suffix.lower()
    if extensao == ".json":
        dados = json.loads(conteudo)
        if isinstance(dados, dict):
            dados = dados.get("ips" if tipo == "ip" else "macs", [])
        if not isinstance(dados, list):
            raise ValueError("JSON deve conter uma lista, ou chaves ips / macs.")
        if len(dados) > MAX_REGISTROS:
            raise ValueError("Arquivo contém registros acima do limite.")
        return [str(e).strip() for e in dados if str(e).strip()]
    if extensao == ".csv":
        linhas = list(csv.reader(io.StringIO(conteudo)))
        if not linhas:
            return []
        nomes = {"ip", "ipv4", "ipv6", "endereco_ip", "endereço_ip"} if tipo == "ip" else {"mac", "endereco_mac", "endereço_mac"}
        cabecalho = [c.strip().lower().replace(" ", "_") for c in linhas[0]]
        coluna = next((i for i, c in enumerate(cabecalho) if c in nomes), 0)
        inicio = 1 if any(c in nomes for c in cabecalho) else 0
        valores = [linha[coluna].strip() for linha in linhas[inicio:] if len(linha) > coluna and linha[coluna].strip()]
        if len(valores) > MAX_REGISTROS:
            raise ValueError("Arquivo CSV contém registros acima do limite.")
        return valores
    return ler_linhas(conteudo, tipo.upper())


def importar_arquivos(arquivo_ip, arquivo_mac, ips_atual, macs_atual):
    """Arquivos enviados substituem apenas o campo correspondente."""
    try:
        if not arquivo_ip and not arquivo_mac:
            return ips_atual, macs_atual, "Selecione um arquivo IP e/ou MAC para importar."
        ips_novos = _ler_registros(str(arquivo_ip), "ip") if arquivo_ip else None
        macs_novos = _ler_registros(str(arquivo_mac), "mac") if arquivo_mac else None
        return ("\n".join(ips_novos) if ips_novos is not None else ips_atual,
                "\n".join(macs_novos) if macs_novos is not None else macs_atual,
                f"Importação concluída. **{len(ips_novos) if ips_novos is not None else 'inalterados'} IP(s)**; "
                f"**{len(macs_novos) if macs_novos is not None else 'inalterados'} MAC(s)**. "
                "Clique em **Analisar registros** para validar.")
    except (ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
        return ips_atual, macs_atual, f"**Falha na importação:** {exc}"


def criar_interface():
    with gr.Blocks(title="Aula 07 | Painel de Análise de Evidências") as painel:
        gr.HTML("""<section id="hero"><h1>Painel de Análise de Artefatos Digitais</h1>
        <p>PMGO · SENAC · Aula 07 | Python aplicado à análise de IPs, MACs e relatórios verificáveis</p></section>""")
        gr.Markdown("**Modo de laboratório:** os valores iniciais são os exemplos didáticos da aula. "
                    "O painel não realiza captura de rede nem identifica autoria de infrações.")
        with gr.Tabs():
            with gr.Tab("01 · Análise"):
                with gr.Row(equal_height=True):
                    with gr.Column(scale=1):
                        ips_input = gr.Textbox(value="\n".join(EXEMPLO_IPS), label="Endereços IP",
                                               info="Um IP por linha; dados originais do exercício", lines=7)
                        macs_input = gr.Textbox(value="\n".join(EXEMPLO_MACS), label="Endereços MAC",
                                                info="Um MAC por linha; valores incompletos serão sinalizados", lines=6)
                        alvo_input = gr.Textbox(value=IP_ALVO_PADRAO, label="IP de interesse")
                        with gr.Row():
                            analisar_btn = gr.Button("Analisar registros", variant="primary")
                            repor_btn = gr.Button("Repor exemplos didáticos", variant="secondary")
                    with gr.Column(scale=2):
                        indicadores = gr.HTML(label="Indicadores")
                        resumo = gr.Markdown()
                        with gr.Accordion("Registros IP e validações", open=True):
                            tabela_ip = gr.Dataframe(headers=["#", "IP informado", "Normalizado", "Status", "Classe", "IP alvo", "Observação"],
                                                      interactive=False, wrap=True, label="Registros IP")
                        with gr.Accordion("Registros MAC e validações", open=True):
                            tabela_mac = gr.Dataframe(headers=["#", "MAC informado", "Normalizado", "Status", "Observação"],
                                                       interactive=False, wrap=True, label="Registros MAC")
                analisar_btn.click(analisar_entrada, [ips_input, macs_input, alvo_input],
                                    [indicadores, resumo, tabela_ip, tabela_mac])
                repor_btn.click(lambda: ("\n".join(EXEMPLO_IPS), "\n".join(EXEMPLO_MACS), IP_ALVO_PADRAO),
                                 outputs=[ips_input, macs_input, alvo_input]).then(
                                     analisar_entrada, [ips_input, macs_input, alvo_input],
                                     [indicadores, resumo, tabela_ip, tabela_mac])
            with gr.Tab("02 · Importar arquivos"):
                gr.Markdown("Envie arquivos **TXT, CSV ou JSON** com até **2 MB**. "
                            "A importação substitui somente o campo correspondente na aba Análise; "
                            "não executa comandos ou scripts enviados.")
                with gr.Row():
                    upload_ip = gr.File(label="Arquivo de IPs", file_types=[".txt", ".csv", ".json"], type="filepath")
                    upload_mac = gr.File(label="Arquivo de MACs", file_types=[".txt", ".csv", ".json"], type="filepath")
                btn_importar = gr.Button("Importar para análise", variant="primary")
                resultado_importacao = gr.Markdown()
                btn_importar.click(importar_arquivos,
                    [upload_ip, upload_mac, ips_input, macs_input],
                    [ips_input, macs_input, resultado_importacao])
                gr.Markdown("**Exemplos de formatos:** TXT com um valor por linha; "
                            "CSV com coluna `ip` ou `mac`; JSON como ` {\"ips\":[\"10.0.0.5\"], \"macs\":[\"AA:BB:CC:DD:EE:FF\"]} `.")
            with gr.Tab("03 · Relatórios e downloads"):
                gr.Markdown("Preencha apenas informações confirmadas. Não confunda a data de geração com a data de coleta.")
                with gr.Row():
                    with gr.Column():
                        identificador = gr.Textbox(value="AULA07-LAB", label="Identificador do relatório")
                        analista = gr.Textbox(value="", label="Analista responsável", placeholder="Informe quem executou a análise")
                        unidade = gr.Textbox(value="PMGO / SENAC — Aula 07 (laboratório)", label="Unidade / curso")
                        origem = gr.Textbox(value="Listas didáticas fornecidas na apresentação da Aula 07", label="Origem declarada")
                        data_coleta = gr.Textbox(value="", label="Data/hora da coleta original (se conhecida)", placeholder="Deixe vazio se não houver registro")
                        observacoes = gr.Textbox(value="Exercício de laboratório com valores didáticos; não foram analisados logs brutos.",
                                                 label="Observações e limites", lines=3)
                        btn_pdf = gr.Button("Gerar relatório e pacote ZIP", variant="primary")
                    with gr.Column():
                        saida_geracao = gr.Markdown("Clique em **Gerar relatório e pacote ZIP** para produzir os arquivos.")
                        arquivo_pdf = gr.File(label="PDF técnico", interactive=False)
                        arquivo_json = gr.File(label="Manifesto JSON", interactive=False)
                        arquivo_hash = gr.File(label="Verificação SHA256SUMS.txt", interactive=False)
                        arquivo_zip = gr.File(label="Pacote completo ZIP", interactive=False)
                btn_pdf.click(gerar_arquivos,
                    [ips_input, macs_input, alvo_input, identificador, analista, unidade,
                     origem, data_coleta, observacoes],
                    [arquivo_pdf, arquivo_json, arquivo_hash, arquivo_zip, saida_geracao])
            with gr.Tab("04 · Sobre e limitações"):
                gr.Markdown("""### O que este painel faz
- Valida IPs (IPv4/IPv6), normaliza MACs de 48 bits e indica registros incompletos.
- Pesquisa um IP de interesse e conta ocorrências e duplicidades.
- Gera PDF técnico, JSON com metadados e registros, arquivo SHA-256 e pacote ZIP.

### O que ele não faz
- Não captura pacotes, não varre redes e não atribui origem, autoria ou criminalidade.
- Não autentica logs originais nem estabelece cadeia de custódia pericial apenas por usar hashes.
- Não salva automaticamente os arquivos no Drive; faça download dos arquivos e arquive-os na pasta do curso.

### Uso adequado
Utilize dados didáticos ou registros autorizados. Um link público temporário do Colab pode ser acessado por quem o possuir; não o use para conteúdo sensível.""")
        painel.load(analisar_entrada, [ips_input, macs_input, alvo_input],
                    [indicadores, resumo, tabela_ip, tabela_mac])
    return painel


demo = criar_interface()

if __name__ == "__main__":
    # Em Windows/Linux, a aplicação fica acessível somente neste computador.
    demo.launch(server_name="127.0.0.1", server_port=7860, share=False,
                theme=gr.themes.Soft(primary_hue="blue", neutral_hue="slate"), css=CSS,
                max_file_size="2mb")
