// Núcleo independente da interface: registro, validação e exportação.
export const IP_ALVO_PADRAO = "192.168.0.99";
export const LIMITE_REGISTROS = 1500;
export const LIMITE_TEXTO = 2500;
const TIPOS = new Set(["IP", "MAC"]);
const SITUACOES = new Set(["pendente", "revisado", "inconclusivo"]);

export function validarIPv4(valor) {
  const p = String(valor).trim().split(".");
  if (p.length !== 4 || !p.every(x => /^\d{1,3}$/.test(x) && Number(x) <= 255 && (x === "0" || !x.startsWith("0")))) return null;
  return p.map(Number).join(".");
}
export function validarIP(valor) {
  const s = String(valor || "").trim();
  const v4 = validarIPv4(s);
  if (v4 !== null) return { valido:true, normalizado:v4, detalhe:"IPv4" };
  if (s.includes(":") && /^[0-9a-fA-F:.]+$/.test(s) && s.length <= 45 && s.includes("::") || (
       s.includes(":") && /^[0-9a-fA-F:.]+$/.test(s) && s.split(":").length === 8)) {
    try {
      const host = new URL("http://[" + s + "]/").hostname;
      if (host.startsWith("[") && host.endsWith("]")) return { valido:true, normalizado:host.slice(1,-1), detalhe:"IPv6" };
    } catch (_) {}
  }
  return { valido:false, normalizado:s, detalhe:"IP inválido ou incompleto" };
}
export function validarMAC(valor) {
  const s = String(valor || "").trim().toUpperCase();
  const limpo = s.replace(/[:-]/g, "");
  if (/^[0-9A-F]{12}$/.test(limpo) && (/^[0-9A-F]{12}$/.test(s) || /^([0-9A-F]{2}[:-]){5}[0-9A-F]{2}$/.test(s))) {
    return { valido:true, normalizado:limpo.match(/../g).join(":"), detalhe:"MAC completo (48 bits)" };
  }
  return { valido:false, normalizado:s, detalhe:"MAC inválido ou incompleto (exigidos 6 octetos)" };
}
export function validarRegistro(tipo, valor) {
  return tipo === "IP" ? validarIP(valor) : tipo === "MAC" ? validarMAC(valor) :
    {valido:false,normalizado:String(valor || ""),detalhe:"Tipo desconhecido"};
}
export function campoTexto(v, max = LIMITE_TEXTO) {
  return String(v ?? "").trim().slice(0,max);
}
export function sanitizarRegistro(raw) {
  if (!raw || typeof raw !== "object") throw new Error("Registro inválido.");
  const tipo = String(raw.tipo || "").toUpperCase();
  if (!TIPOS.has(tipo)) throw new Error("Tipo deve ser IP ou MAC.");
  const valor = campoTexto(raw.valor,128);
  if (!valor) throw new Error("Informe o endereço IP ou MAC.");
  const status = SITUACOES.has(raw.status) ? raw.status : "pendente";
  const dataColeta = campoTexto(raw.dataColeta,40);
  const criadoEm = campoTexto(raw.criadoEm,40);
  return {
    id:campoTexto(raw.id,80), tipo, valor,
    origem:campoTexto(raw.origem,240),
    responsavel:campoTexto(raw.responsavel,160),
    dataColeta, status,
    observacoes:campoTexto(raw.observacoes,LIMITE_TEXTO),
    criadoEm, atualizadoEm:campoTexto(raw.atualizadoEm,40)
  };
}
export function resumir(registros, alvo = IP_ALVO_PADRAO) {
  const a = validarIP(alvo);
  const ips = registros.filter(r=>r.tipo==="IP");
  const macs = registros.filter(r=>r.tipo==="MAC");
  const ipsValidos = ips.filter(r=>validarIP(r.valor).valido);
  const macsValidos = macs.filter(r=>validarMAC(r.valor).valido);
  const localizados = a.valido ? ipsValidos.filter(r=>validarIP(r.valor).normalizado===a.normalizado).length : 0;
  const chaves = registros.map(r=>r.tipo+":"+validarRegistro(r.tipo,r.valor).normalizado);
  return {
    total:registros.length, ips:ips.length, macs:macs.length,
    validos:ipsValidos.length+macsValidos.length,
    incompletos:registros.length-ipsValidos.length-macsValidos.length,
    duplicados:chaves.length-new Set(chaves).size,
    alvoLocalizado:localizados,
    alvoValido:a.valido
  };
}
function celulaCsv(valor) {
  let s = String(valor ?? "").replace(/\r?\n/g," ");
  if (/^[\s]*[=+@-]/.test(s)) s = "'" + s; // evita execução de fórmulas em planilhas
  return '"' + s.replace(/"/g,'""') + '"';
}
export function gerarCSV(registros) {
  const campos=["id","tipo","valor","origem","responsavel","dataColeta","status","observacoes","criadoEm","atualizadoEm"];
  return "\uFEFF" + campos.join(";") + "\r\n" + registros.map(r=>campos.map(k=>celulaCsv(r[k])).join(";")).join("\r\n") + "\r\n";
}
export function extrairImportacao(dados) {
  let origem = dados;
  if (!Array.isArray(origem) && origem && Array.isArray(origem.registros)) origem = origem.registros;
  if (!Array.isArray(origem)) {
    // Compatibilidade com manifesto do gerador Python.
    if (dados && Array.isArray(dados.registros_ip) && Array.isArray(dados.registros_mac)) {
      origem = [
        ...dados.registros_ip.map(r=>({tipo:"IP",valor:r.informado,origem:"Manifesto Python importado",status:"pendente"})),
        ...dados.registros_mac.map(r=>({tipo:"MAC",valor:r.informado,origem:"Manifesto Python importado",status:"pendente"}))
      ];
    } else throw new Error("JSON deve conter um array, 'registros' ou registros_ip/registros_mac.");
  }
  if (origem.length > LIMITE_REGISTROS) throw new Error("Quantidade de registros excede o limite.");
  return origem.map(sanitizarRegistro);
}
export const EXEMPLOS_AULA = Object.freeze([
  ...["10.0.0.5","172.16.0.3","192.168.0.99","192.168.1.10","10.10.0.22"].map(valor=>({tipo:"IP",valor,origem:"Exemplo didático — slide 11",status:"pendente"})),
  ...["00:1A:2B","FF:EE:DD","12:34:56","AA:BB:CC:DD:EE:FF"].map(valor=>({tipo:"MAC",valor,origem:"Exemplo didático — slides 7 e 8",status:"pendente"}))
]);
