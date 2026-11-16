# Executar no Windows

Na pasta python, execute INICIAR_NO_WINDOWS.bat. Alternativamente:

    py -3 -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    .\.venv\Scripts\python.exe app.py

Abra http://127.0.0.1:7860. A aplicação permanece local.

O painel original Gradio permite importar TXT/CSV/JSON, visualizar análises e gerar PDF, JSON, hashes e ZIP. A interface de cadastro persistente demonstrativa está na raiz do GitHub Pages e utiliza armazenamento local do navegador, não banco de dados de produção.
