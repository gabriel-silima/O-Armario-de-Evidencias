import test from "node:test";
import assert from "node:assert/strict";
import { validarIP, validarMAC, sanitizarRegistro, resumir, gerarCSV, extrairImportacao, EXEMPLOS_AULA } from "../src/logic.mjs";
test("IPs", ()=>{
  assert.equal(validarIP("192.168.0.99").valido,true);
  assert.equal(validarIP("256.1.1.1").valido,false);
  assert.equal(validarIP("192.168.00.1").valido,false);
  assert.equal(validarIP("2001:db8::1").valido,true);
});
test("MAC completo e incompleto", ()=>{
  assert.equal(validarMAC("AA-BB-CC-DD-EE-FF").normalizado,"AA:BB:CC:DD:EE:FF");
  assert.equal(validarMAC("00:1A:2B").valido,false);
});
test("Dados do professor geram contagens honestas", ()=>{
  const a=EXEMPLOS_AULA.map(sanitizarRegistro), r=resumir(a);
  assert.equal(r.total,9);assert.equal(r.ips,5);assert.equal(r.macs,4);
  assert.equal(r.validos,6);assert.equal(r.incompletos,3);assert.equal(r.alvoLocalizado,1);
});
test("CSV neutraliza fórmulas", ()=>{
  assert.ok(gerarCSV([{origem:"=2+2"}]).includes("'=2+2"));
});
test("Importação exige estrutura", ()=>{
  assert.equal(extrairImportacao({registros:[{tipo:"IP",valor:"10.0.0.1"}]}).length,1);
  assert.throws(()=>extrairImportacao({hello:true}));
});
