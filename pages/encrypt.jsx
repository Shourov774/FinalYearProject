import React from "react";
import { useState, useEffect, useRef } from "react";

import DropZone from "../components/dropZone";
import Terminal from "../components/terminal";
import { genAES, genRSA, aesEnc, aesDec, rsaEnc, rsaDec, exportRaw, importAES, hmacSign, hmacVerify, sha256, toHex, toB64, fmtB, sleep, now, readFile } from "../cryotoFunction";
import Prog from "../components/progs";
import "../CSS/status.css";
import "../CSS/card.css";
import "../CSS/btn.css";

export default function Encrypt() {

  const [ file, setFile ] = useState(null);
  const [ rsaBits, setRsaBits ] = useState("2048");
  const [ running, setRunning ] = useState(false);
  const [ logs, setLogs ] = useState([]);
  const [ prog, setProg ] = useState(0);
  const [ result, setResult ] = useState(null);
  const store = useRef({});

  const log = (k,m) => {
    setLogs( l => [...l, { t : now(), k, m }]);
  };

  const run = async() => {

    if( !file ) {
      return;
      setRunning(true);
      setLogs([]);
      setProg(0);
      setResult(null);
    }

    try{
      const T = performance.now();
      log("INFO",`Loaded: ${file.name} (${fmtB(file.size)})`);
      await sleep(100);

      log( "INFO",`Generating RSA-${ rsaBits } key pair (OAEP / SHA-256)...`);
      const t1 = performance.now();
      const rsaKP = await genRSA(parseInt(rsaBits));
      const rsaT = ( performance.now()-t1).toFixed(0);
      log( "OK",`RSA key pair ready in ${rsaT}ms`);
      setProg(15);

      log("INFO","Generating AES-256 session key...");
      const aesK = await genAES();
      const aesRaw = await exportRaw(aesK);
      log( "DATA",`Session key: ${toHex(aesRaw).slice(0,20)}... [256-bit]`);setProg(25);
      await sleep(60);

      const fileBytes = await readFile(file);
      log("INFO",`File : ${fmtB(fileBytes.byteLength)}`);

      log("INFO","Computing SHA-256 fingerprint...");
      const t2 = performance.now();
      const fileHash = await sha256(fileBytes);
      const hashT = (performance.now()-t2).toFixed(0);
      log("DATA",`SHA-256: ${fileHash}`);setProg(38);

      log("INFO","Computing HMAC-SHA256 for integrity...");
      const hmacSig = await hmacSign(aesRaw,fileBytes);
      log("DATA",`HMAC: ${toHex(hmacSig).slice(0,32)}...`);setProg(50);
      await sleep(60);

      log("INFO","Encrypting file with AES-256-GCM...");
      const t3 = performance.now();
      const {iv,ct} = await aesEnc(aesK,fileBytes);
      const aesT = (performance.now()-t3).toFixed(0);
      log("OK",`AES-GCM done in ${aesT}ms | IV: ${toHex(iv)} | CT: ${fmtB(ct.byteLength)}`);setProg(68);
      await sleep(60);

      log("INFO",`Wrapping AES key with RSA-${rsaBits} public key (OAEP)...`);
      const t4 = performance.now();
      const wrapped = await rsaEnc(rsaKP.publicKey,aesRaw);
      const wrapT = (performance.now()-t4).toFixed(0);
      log("OK",`Key wrapped in ${wrapT}ms`);
      log("DATA",`Wrapped: ${toB64(wrapped).slice(0,48)}...`);setProg(85);
      await sleep(60);

      const total = (performance.now()-T).toFixed(0);
      log("OK",`✓ Digital envelope sealed. Total: ${total}ms`);setProg(100);

      store.current={rsaKP,iv,ct,wrapped,fileHash,hmacSig,aesRaw,aesK};
      setResult({
        fileHash,iv:toHex(iv),wrapped:toB64(wrapped).slice(0,56)+"...",
        ctSize:ct.byteLength,origSize:fileBytes.byteLength,
        perf:{rsa:rsaT,aes:aesT,wrap:wrapT,hash:hashT,total}
      });
    }catch(e){log("ERR",e.message)}
    setRunning(false);
  };

  return(
    <div>
      <div className="page-header">
        <div className="page-title">🔒 Encrypt File</div>
        <div className="page-sub">Phase 1-2: Key generation → AES-256-GCM encryption → RSA-OAEP key wrapping → SHA-256 + HMAC integrity</div>
      </div>

      <div className="card">
        <div className="card-hd"><div className="chip cyan">🔑</div><div><div className="card-title">File & Configuration</div><div className="card-desc">Select file and cryptographic parameters</div></div></div>
        <div className="field"><label>File to Encrypt</label><DropZone file={file} onChange={setFile}/></div>
        <div className="row2">
          <div className="field" style={{marginBottom:0}}><label>RSA Key Size</label>
            <select className="inp" value={rsaBits} onChange={e=>setRsaBits(e.target.value)}>
              <option value="2048">RSA-2048 (Standard)</option>
              <option value="3072">RSA-3072 (NIST Post-2030)</option>
              <option value="4096">RSA-4096 (High Security)</option>
            </select>
          </div>
          <div className="field" style={{marginBottom:0}}><label>Symmetric Cipher</label>
            <select className="inp" disabled><option>AES-256-GCM (Authenticated Encryption)</option></select>
          </div>
        </div>
        <div className="flex-end">
          <button className="btn btn-c" onClick={run} disabled={!file||running}>
            {running?"⏳ Encrypting...":"🔒 Encrypt File"}
          </button>
        </div>
      </div>

      {logs.length>0&&(
        <div className="card">
          <div className="card-hd"><div className="chip amber">⚙️</div><div><div className="card-title">Execution Log</div><div className="card-desc">Real cryptographic operations via Web Crypto API</div></div></div>
          {prog>0&&<Prog val={prog} color="c" label="AES-256-GCM Encryption Pipeline"/>}
          <Terminal logs={logs} running={running}/>
        </div>
      )}

      {result&&(
        <>
          <div className="card">
            <div className="card-hd"><div className="chip green">✅</div><div><div className="card-title">Encrypted Envelope</div><div className="card-desc">Cryptographic outputs — ready for secure transmission</div></div></div>
            <div className="status ok mt8" style={{marginBottom:14}}>✓ Digital envelope sealed — AES-GCM + HMAC + SHA-256</div>
            <div className="grid2">
              <div className="obox"><div className="olbl">SHA-256 Fingerprint</div><div className="oval purple">{result.fileHash.slice(0,32)}<br/>{result.fileHash.slice(32)}</div></div>
              <div className="obox"><div className="olbl">AES-GCM IV (96-bit nonce)</div><div className="oval cyan">{result.iv}</div></div>
              <div className="obox"><div className="olbl">RSA-Wrapped AES Session Key</div><div className="oval amber">{result.wrapped}</div></div>
              <div className="obox"><div className="olbl">Ciphertext Size</div><div className="oval green">{fmtB(result.ctSize)} <span style={{color:"var(--muted)"}}>← original: {fmtB(result.origSize)}</span></div></div>
            </div>
          </div>
          <div className="card">
            <div className="card-hd"><div className="chip purple">📊</div><div><div className="card-title">Performance Metrics</div><div className="card-desc">Computational cost per operation</div></div></div>
            <div className="perf-grid">
              <div className="pbox"><div className="pval" style={{color:"var(--cyan)"}}>{result.perf.rsa}</div><div className="punit">ms · RSA keygen</div></div>
              <div className="pbox"><div className="pval" style={{color:"var(--green)"}}>{result.perf.aes}</div><div className="punit">ms · AES-GCM enc</div></div>
              <div className="pbox"><div className="pval" style={{color:"var(--amber)"}}>{result.perf.wrap}</div><div className="punit">ms · RSA key wrap</div></div>
              <div className="pbox"><div className="pval" style={{color:"var(--purple)"}}>{result.perf.total}</div><div className="punit">ms · total</div></div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}