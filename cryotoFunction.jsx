import React from "react";

const cry = window.crypto.subtle;

async function genRSA(bits=2048){
  return cry.generateKey({name:"RSA-OAEP",modulusLength:bits,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},true,["encrypt","decrypt"]);
}
async function genAES(){
  return cry.generateKey({name:"AES-GCM",length:256},true,["encrypt","decrypt"]);
}
async function exportRaw(k){return cry.exportKey("raw",k)}
async function importAES(raw){return cry.importKey("raw",raw,{name:"AES-GCM"},false,["encrypt","decrypt"])}
async function aesEnc(k,data){
  const iv=window.crypto.getRandomValues(new Uint8Array(12));
  const ct=await cry.encrypt({name:"AES-GCM",iv},k,data);
  return {iv,ct:new Uint8Array(ct)};
}
async function aesDec(k,iv,ct){return cry.decrypt({name:"AES-GCM",iv},k,ct)}
async function rsaEnc(pub,data){return cry.encrypt({name:"RSA-OAEP"},pub,data)}
async function rsaDec(priv,data){return cry.decrypt({name:"RSA-OAEP"},priv,data)}
async function sha256(data){
  const h=await cry.digest("SHA-256",data);
  return Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function hmacSign(key,data){
  const k=await cry.importKey("raw",key,{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const sig=await cry.sign("HMAC",k,data);
  return new Uint8Array(sig);
}
async function hmacVerify(key,sig,data){
  const k=await cry.importKey("raw",key,{name:"HMAC",hash:"SHA-256"},false,["verify"]);
  return cry.verify("HMAC",k,sig,data);
}

const toHex=buf=>Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
const toB64=buf=>btoa(String.fromCharCode(...new Uint8Array(buf)));
const fmtB=n=>n<1024?n+" B":n<1048576?(n/1024).toFixed(1)+" KB":(n/1048576).toFixed(2)+" MB";
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const now=()=>new Date().toLocaleTimeString("en",{hour12:false});
const readFile=f=>new Promise((r,j)=>{const fr=new FileReader();fr.onload=()=>r(fr.result);fr.onerror=j;fr.readAsArrayBuffer(f);});

export {genAES,genRSA,aesEnc,aesDec,rsaEnc,rsaDec,exportRaw,importAES,hmacSign,hmacVerify,sha256,toHex,toB64,fmtB,sleep,now,readFile};