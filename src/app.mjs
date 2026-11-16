import {
  IP_ALVO_PADRAO,LIMITE_REGISTROS,validarIP,validarRegistro,
  sanitizarRegistro,resumir,gerarCSV,extrairImportacao,EXEMPLOS_AULA
} from "./logic.mjs";

const CHAVE="armario-evidencias-local-v1";
let acervo={registros:[],historico:[]};
let editando=null;

const $=id=>document.getElementById(id);
function agora(){return new Date().toISOString();}
function formatarData(v){
  if(!v)return "Não informada";
  const d=new Date(v);return Number.isNaN(d.getTime())?v:d.toLocaleString("pt-BR");
}
function criarId(){
  return typeof crypto.randomUUID==="function"?crypto.randomUUID():
    "registro-"+Date.now()+"-"+Math.random().toString(36).slice(2);
}
function notificar(msg,erro=false){
  const el=$("feedback");el.textContent=msg;el.hidden=false;el.classList.toggle("error",erro);
  el.scrollIntoView({behavior:"smooth",block:"nearest"});
}
function carregar(){
  try {
    const v=localStorage.getItem(CHAVE);
    if(v){
      const dados=JSON.parse(v);
      if(Array.isArray(dados.registros)){
        acervo.registros=dados.registros.slice(0,LIMITE_REGISTROS).map(sanitizarRegistro);
        acervo.historico=Array.isArray(dados.historico)?dados.historico.slice(0,300):[];
      }
    }
  } catch(e){notificar("Não foi possível ler o acervo local: "+e.message,true);}
}
function salvar(){
  try {
    localStorage.setItem(CHAVE,JSON.stringify(acervo));
    return true;
  } catch(e){
    notificar("Falha ao salvar neste navegador (armazenamento desativado ou cheio). Exporte um backup: "+e.message,true);
    return false;
  }
}
function evento(acao,r){
  acervo.historico.unshift({id:criarId(),acao,registroId:r?.id||"",descricao:r? r.tipo+" · "+r.valor:"",em:agora()});
  acervo.historico=acervo.historico.slice(0,300);
}
const TITULOS={inicio:"Visão geral do acervo",cadastro:"Cadastro de registros",acervo:"Acervo de registros",exportar:"Importar e exportar"};
function navegar(pagina){
  for(const p of document.querySelectorAll(".page")) p.classList.toggle("active",p.id==="view-"+pagina);
  for(const b of document.querySelectorAll(".nav-link")){
    const ativo=b.dataset.view===pagina;b.classList.toggle("active",ativo);
    if(ativo)b.setAttribute("aria-current","page");else b.removeAttribute("aria-current");
  }
  $("page-title").textContent=TITULOS[pagina]||"O Armário de Evidências";
  $("feedback").hidden=true;
  window.scrollTo({top:0,behavior:"smooth"});
}
function td(tr,text,sub=null){
  const c=document.createElement("td");
  if(sub!==null){
    const b=document.createElement("strong");b.textContent=text;c.append(b);
    const sm=document.createElement("small");sm.textContent=sub;c.append(sm);
  }else c.textContent=text;
  tr.append(c);return c;
}
function etiqueta(valor,ruim=false){
  const s=document.createElement("span");s.className="pill"+(ruim?" bad":"");
  s.textContent=valor;return s;
}
function renderizar(){
  const alvo=$("target").value||IP_ALVO_PADRAO;
  const k=resumir(acervo.registros,alvo);
  $("stat-total").textContent=k.total;
  $("stat-valid").textContent=k.validos;
  $("stat-invalid").textContent=k.incompletos;
  $("stat-target").textContent=k.alvoLocalizado;
  const recentes=$("recent-list");recentes.replaceChildren();
  const lista=[...acervo.registros].sort((a,b)=>b.criadoEm.localeCompare(a.criadoEm)).slice(0,5);
  if(!lista.length){const p=document.createElement("p");p.className="empty";p.textContent="Nenhum registro cadastrado. Inicie pelo formulário ou carregue os exemplos do professor.";recentes.append(p);}
  for(const r of lista){
    const v=validarRegistro(r.tipo,r.valor),item=document.createElement("div");item.className="recent-item";
    const box=document.createElement("div"),b=document.createElement("strong"),sm=document.createElement("small");
    b.textContent=r.valor;sm.textContent=r.tipo+" · "+(r.origem||"Origem não informada");box.append(b,sm);
    item.append(box,etiqueta(v.valido?"Formato válido":"Revisar formato",!v.valido));recentes.append(item);
  }
  const busca=$("search").value.trim().toLocaleLowerCase("pt-BR");
  const tipo=$("filter-type").value,stat=$("filter-status").value;
  const filtrados=[...acervo.registros].filter(r=>
    (!tipo||r.tipo===tipo)&&(!stat||r.status===stat)&&
    (!busca||[r.valor,r.origem,r.responsavel,r.observacoes,r.status].some(v=>String(v).toLocaleLowerCase("pt-BR").includes(busca)))
  ).sort((a,b)=>b.criadoEm.localeCompare(a.criadoEm));
  $("table-count").textContent=filtrados.length+" de "+acervo.registros.length+" registros";
  const body=$("records-body");body.replaceChildren();
  if(!filtrados.length){const tr=document.createElement("tr"),c=td(tr,"Nenhum registro encontrado.");c.colSpan=6;body.append(tr);}
  for(const r of filtrados){
    const v=validarRegistro(r.tipo,r.valor),tr=document.createElement("tr");
    const t=td(tr,"");t.append(etiqueta(r.tipo));
    td(tr,r.valor,(v.valido?"Válido sintaticamente":"Incompleto / inválido")+" · "+v.detalhe);
    td(tr,r.origem||"Não informada");
    const s=td(tr,"");s.append(etiqueta(r.status));
    td(tr,formatarData(r.criadoEm));
    const actions=td(tr,"");
    for(const [name,action,danger] of [["Editar","edit",false],["Excluir","delete",true]]){
      const btn=document.createElement("button");btn.type="button";btn.className="action-btn"+(danger?" danger":"");
      btn.textContent=name;btn.dataset.action=action;btn.dataset.id=r.id;actions.append(btn);
    }
    body.append(tr);
  }
  const history=$("history");history.replaceChildren();
  if(!acervo.historico.length){const p=document.createElement("p");p.className="empty";p.textContent="Nenhuma operação registrada.";history.append(p);}
  for(const h of acervo.historico.slice(0,30)){
    const row=document.createElement("div");row.className="event";const desc=document.createElement("span"),when=document.createElement("small");
    desc.textContent=String(h.acao||"Operação")+" — "+String(h.descricao||"");when.textContent=formatarData(h.em);row.append(desc,when);history.append(row);
  }
}
function limparFormulario(){
  $("record-form").reset();editando=null;$("form-heading").textContent="Adicionar novo registro";
  $("save-label").textContent="Salvar registro";$("form-validation").textContent="IPs IPv4/IPv6 e MACs completos são reconhecidos; valores incompletos podem ser registrados com aviso.";
}
function salvarFormulario(event){
  event.preventDefault();
  let dados;
  try {
    dados=sanitizarRegistro(Object.fromEntries(["tipo","valor","origem","responsavel","dataColeta","status","observacoes"].map(id=>[id,$(id).value])));
  }catch(e){notificar(e.message,true);return;}
  const val=validarRegistro(dados.tipo,dados.valor);
  if(!val.valido && !window.confirm("O valor informado não possui formato completo. Deseja registrar mesmo assim para revisão, mantendo o valor bruto?"))return;
  const anterior=editando?acervo.registros.find(r=>r.id===editando):null;
  if(editando&&!anterior){notificar("Registro não encontrado para edição.",true);return;}
  if(!editando&&acervo.registros.length>=LIMITE_REGISTROS){notificar("Limite local de registros atingido. Exporte um backup.",true);return;}
  const nova={
    ...dados,id:anterior?.id||criarId(),criadoEm:anterior?.criadoEm||agora(),atualizadoEm:agora()
  };
  const copia=structuredClone(acervo);
  if(anterior) acervo.registros=acervo.registros.map(r=>r.id===anterior.id?nova:r);
  else acervo.registros.push(nova);
  evento(anterior?"Registro alterado":"Registro incluído",nova);
  if(!salvar()){acervo=copia;return;}
  limparFormulario();renderizar();navegar("acervo");
  notificar(val.valido?"Registro salvo. Formato sintaticamente válido.":"Registro salvo como incompleto/inválido para revisão.");
}
function editar(id){
  const r=acervo.registros.find(r=>r.id===id);if(!r)return;
  editando=id;
  for(const f of ["tipo","valor","origem","responsavel","dataColeta","status","observacoes"]) $(f).value=r[f]||"";
  $("form-heading").textContent="Editar registro";$("save-label").textContent="Salvar alterações";navegar("cadastro");
}
function excluir(id){
  const r=acervo.registros.find(r=>r.id===id);if(!r)return;
  if(!window.confirm("Excluir o registro "+r.tipo+" "+r.valor+" apenas deste navegador? Faça backup antes se necessário."))return;
  const copia=structuredClone(acervo);
  acervo.registros=acervo.registros.filter(x=>x.id!==id);evento("Registro excluído",r);
  if(!salvar()){acervo=copia;return;}
  renderizar();notificar("Registro excluído do acervo local.");
}
function carregarExemplos(){
  if(!window.confirm("Adicionar os 9 exemplos didáticos da apresentação? Os registros existentes serão preservados."))return;
  const conhecidos=new Set(acervo.registros.map(r=>r.tipo+":"+r.valor+":"+r.origem));
  const novos=EXEMPLOS_AULA.map(sanitizarRegistro).filter(r=>!conhecidos.has(r.tipo+":"+r.valor+":"+r.origem));
  if(acervo.registros.length+novos.length>LIMITE_REGISTROS){notificar("Limite de registros ultrapassado.",true);return;}
  if(!novos.length){notificar("Os exemplos já estão cadastrados.");return;}
  const copia=structuredClone(acervo);
  for(const r of novos){
    r.id=criarId();r.criadoEm=agora();r.atualizadoEm=r.criadoEm;acervo.registros.push(r);
  }
  evento("Exemplos didáticos adicionados",{id:"",tipo:"SIMULAÇÃO",valor:String(novos.length)+" itens"});
  if(!salvar()){acervo=copia;return;}
  renderizar();notificar(novos.length+" exemplos didáticos cadastrados e identificados como simulação.");
}
function baixarArquivo(conteudo,nome,tipo){
  const blob=new Blob([conteudo],{type:tipo}),url=URL.createObjectURL(blob),a=document.createElement("a");
  a.href=url;a.download=nome;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),2500);
}
function nomeData(){return new Date().toISOString().slice(0,19).replace(/[T:]/g,"-");}
async function exportarBackup(){
  const backup={
    esquema:"armario-evidencias/v1",
    exportadoEm:agora(),
    fonte:"Registros cadastrados localmente no navegador pelo usuário",
    advertencia:"Este backup e histórico local não constituem cadeia de custódia forense.",
    registros:acervo.registros,historico:acervo.historico
  };
  const json=JSON.stringify(backup,null,2)+"\n",nome="armario-evidencias-"+nomeData()+".json";
  try{
    const bytes=new TextEncoder().encode(json);
    const hash=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))).map(x=>x.toString(16).padStart(2,"0")).join("");
    baixarArquivo(json,nome,"application/json;charset=utf-8");
    baixarArquivo(hash+"  "+nome+"\n",nome+".sha256","text/plain;charset=utf-8");
    notificar("Backup JSON e hash SHA-256 gerados. Arquive ambos juntos.");
  }catch(e){notificar("Falha ao calcular SHA-256: "+e.message,true);}
}
async function importar(){
  const f=$("import-file").files[0];
  if(!f){notificar("Selecione um arquivo JSON.",true);return;}
  if(f.size>2*1024*1024){notificar("O limite de importação é 2 MB.",true);return;}
  try{
    const raw=JSON.parse(await f.text()),lista=extrairImportacao(raw);
    if(!lista.length){notificar("O arquivo não possui registros.");return;}
    if(acervo.registros.length+lista.length>LIMITE_REGISTROS){notificar("A importação excederia o limite de "+LIMITE_REGISTROS+".",true);return;}
    if(!window.confirm("Importar "+lista.length+" registros para este navegador? Os registros atuais serão mantidos."))return;
    const copia=structuredClone(acervo);
    for(const r of lista){
      r.id=criarId();r.criadoEm=agora();r.atualizadoEm=r.criadoEm;
      acervo.registros.push(r);
    }
    evento("Arquivo JSON importado",{id:"",tipo:"IMPORTAÇÃO",valor:lista.length+" registros"});
    if(!salvar()){acervo=copia;return;}
    $("import-file").value="";renderizar();notificar(lista.length+" registros importados. Revise origem, data da coleta e formatos.");
  }catch(e){notificar("Falha na importação: "+e.message,true);}
}
function imprimir(){
  const el=$("print-area");el.replaceChildren();
  function linha(tag,txt,pai=el){const x=document.createElement(tag);x.textContent=txt;pai.append(x);return x;}
  linha("h1","Relatório de registros — O Armário de Evidências");
  linha("p","Exercício didático PMGO / SENAC · UC4 — Aula 07");
  linha("p","Data/hora de geração: "+formatarData(agora())+". Não corresponde à data de coleta.");
  const alvo=$("target").value,resultado=resumir(acervo.registros,alvo);
  linha("p","Total: "+resultado.total+" | Sintaticamente válidos: "+resultado.validos+
    " | Incompletos: "+resultado.incompletos+" | Ocorrências do IP de interesse: "+resultado.alvoLocalizado);
  linha("h2","Registros declarados");
  const t=document.createElement("table"),head=document.createElement("tr");
  for(const h of ["Tipo","Valor informado","Validação","Origem","Data da coleta","Situação"]){
    const th=document.createElement("th");th.textContent=h;head.append(th);
  }t.append(head);
  for(const r of acervo.registros){
    const tr=document.createElement("tr");
    for(const v of [r.tipo,r.valor,validarRegistro(r.tipo,r.valor).detalhe,r.origem||"Não informada",r.dataColeta||"Não informada",r.status]){
      const c=document.createElement("td");c.textContent=v;tr.append(c);
    }t.append(tr);
  }el.append(t);
  linha("h2","Limitações");
  linha("p","Os dados desta página foram informados ou importados pelo usuário. A validação é sintática e não comprova origem, conexão, intrusão, autoria, integridade do arquivo original ou cadeia de custódia jurídica.");
  navegar("exportar");
  window.print();
}
function apagarTudo(){
  if(!acervo.registros.length){notificar("Acervo já está vazio.");return;}
  if(!window.confirm("Apagar todos os registros e histórico deste navegador? Esta operação não poderá ser desfeita sem backup."))return;
  if(!window.confirm("Confirma a exclusão definitiva do acervo LOCAL?"))return;
  const copia=structuredClone(acervo);acervo={registros:[],historico:[]};
  if(!salvar()){acervo=copia;return;}
  renderizar();notificar("Acervo local apagado. Os arquivos exportados permanecem onde foram salvos.");
}
function ligarEventos(){
  for(const btn of document.querySelectorAll("[data-view]"))btn.addEventListener("click",()=>navegar(btn.dataset.view));
  for(const id of ["top-new","hero-new"])$(id).addEventListener("click",()=>{limparFormulario();navegar("cadastro");});
  for(const id of ["load-examples","secondary-examples"])$(id).addEventListener("click",carregarExemplos);
  $("record-form").addEventListener("submit",salvarFormulario);
  $("cancel-edit").addEventListener("click",limparFormulario);
  $("tipo").addEventListener("change",()=>{
    $("valor").placeholder=$("tipo").value==="MAC"?"Ex.: AA:BB:CC:DD:EE:FF":"Ex.: 192.168.0.99";
  });
  $("valor").addEventListener("input",()=>{
    const s=$("valor").value;if(!s)return;
    const v=validarRegistro($("tipo").value,s);
    $("form-validation").textContent=v.valido?"Formato reconhecido: "+v.detalhe:"Formato não reconhecido: "+v.detalhe;
  });
  for(const id of ["search","filter-type","filter-status","target"])$(id).addEventListener("input",renderizar);
  $("records-body").addEventListener("click",e=>{
    const btn=e.target.closest("button[data-action]");if(!btn)return;
    if(btn.dataset.action==="edit")editar(btn.dataset.id);
    if(btn.dataset.action==="delete")excluir(btn.dataset.id);
  });
  $("export-json").addEventListener("click",exportarBackup);
  $("export-csv").addEventListener("click",()=>{baixarArquivo(gerarCSV(acervo.registros),"armario-evidencias-"+nomeData()+".csv","text/csv;charset=utf-8");notificar("CSV exportado.");});
  $("print-report").addEventListener("click",imprimir);
  $("import-btn").addEventListener("click",importar);
  $("clear-all").addEventListener("click",apagarTudo);
}
carregar();ligarEventos();renderizar();
