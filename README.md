# O Armário de Evidências

Aplicação acadêmica da Aula 07 — Estruturas de Dados e Cadeia de Custódia (PMGO / SENAC).

Aplicação web: https://gabriel-silima.github.io/O-Armario-de-Evidencias/

## Funcionalidades no GitHub Pages

- Cadastro de IP e MAC, responsável, origem, data de coleta (quando conhecida), status e observações.
- Pesquisa, filtros, edição, exclusão e histórico local de ações.
- Validação sintática de IPv4/IPv6 e endereços MAC de 48 bits; registros incompletos são preservados e sinalizados.
- Importação JSON e exportação JSON com SHA-256, CSV e relatório para salvar como PDF usando a impressão do navegador.
- Exemplos didáticos dos slides disponibilizados somente mediante ação explícita.

**ATENÇÃO: GitHub Pages é estático.** Os novos registros são armazenados somente no localStorage do navegador atual; NÃO são gravados automaticamente no GitHub, não ficam sincronizados entre dispositivos e podem ser perdidos caso os dados de navegação sejam limpos. Exporte backups regularmente. O histórico local pode ser alterado e não constitui trilha de custódia imutável.

## Aplicação Python (Gradio)

O repositório também contém a aplicação completa em python/app.py e o gerador de relatórios em python/Relatorio_Aula07_Gerador.py, além do notebook original Aula07_App_Visual_Colab.ipynb.

A versão Python gera PDF paginado, manifesto JSON, hashes SHA-256 e ZIP. GitHub Pages não executa Python. A versão web usa a opção de impressão do navegador para PDF.

Para iniciar no Windows, execute python/INICIAR_NO_WINDOWS.bat ou os comandos:

    cd python
    py -3 -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    .\.venv\Scripts\python.exe app.py

Abra http://127.0.0.1:7860; o programa usa share=False na execução local.

Para usar no Colab, abra Aula07_App_Visual_Colab.ipynb e execute as células A a D.

## Testes

Com Node.js 20 ou superior:

    npm test

## Limitações

A análise é didática e sintática. Encontrar um IP não demonstra autoria ou invasão. SHA-256 valida os artefatos exportados, não logs externos. A cadeia de custódia real requer coleta comprovada, hashes dos originais, movimentações documentadas, controle de acesso e ferramentas apropriadas. O repositório é público: não registre dados de investigações reais ou credenciais no site.

Para registros sincronizados em diferentes computadores, uma futura versão deverá ter backend autenticado, banco de dados, controle de acesso e auditoria.
