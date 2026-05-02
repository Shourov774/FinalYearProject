import React from "react";
import { useState,useRef } from "react";

import Terminal from "../components/terminal";
import Prog from "../components/progs";
import {genAES,genRSA,aesEnc,aesDec,rsaEnc,rsaDec,exportRaw,importAES,hmacSign,hmacVerify,sha256,toHex,toB64,fmtB,sleep,now,} from "../cryotoFunction";
import "../CSS/status.css";
import "../CSS/card.css";
import "../CSS/btn.css";

export default function Decrypt() {
  const [logs,setLogs]=useState([]);
  const [running,setRunning]=useState(false);
  const [prog,setProg]=useState(0);
  const [result,setResult]=useState(null);
  const [ready,setReady]=useState(false);
  const store=useRef(null);
  const log=(k,m)=>setLogs(l=>[...l,{t:now(),k,m}]);

  const setup=async()=>{
    setLogs([]);setResult(null);setProg(0);
    log("INFO","Generating demo encrypted envelope...");
    const msg="CLASSIFIED DOCUMENT\n═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═\nProject: Hybrid Cryptographic Protocol\nAuthor: Farhad Hasan Shourov \nID:2110579123  — EEE, RU\n\nThis file was encrypted using:\n• AES-256-GCM (file encryption)\n• RSA-2048-OAEP (key wrapping)\n• HMAC-SHA256 (integrity)\n• SHA-256 (fingerprint)\n\nDecryption confirms confidentiality + integrity.";
    const data=new TextEncoder().encode(msg);
    const aesK=await genAES();
    const rsaKP=await genRSA(2048);
    const {iv,ct}=await aesEnc(aesK,data);
    const aesRaw=await exportRaw(aesK);
    const wrapped=await rsaEnc(rsaKP.publicKey,aesRaw);
    const fileHash=await sha256(data);
    const hmacSig=await hmacSign(aesRaw,data);
    store.current={rsaKP,iv,ct,wrapped,fileHash,hmacSig,aesRaw};
    setReady(true);
    log("OK","Demo envelope ready — RSA-2048 + AES-256-GCM + HMAC");
  };

  const run=async()=>{
    if(!store.current)return;
    setRunning(true);setLogs(p=>[...p]);setResult(null);setProg(0);
    const {rsaKP,iv,ct,wrapped,fileHash,hmacSig}=store.current;
    try{
      const T=performance.now();
      log("INFO","Initiating decryption pipeline...");await sleep(80);

      log("INFO","Phase 3: RSA-OAEP private key unwrapping...");
      const t1=performance.now();
      const aesRawDec=await rsaDec(rsaKP.privateKey,wrapped);
      const unwrapT=(performance.now()-t1).toFixed(0);
      log("OK",`Session key recovered in ${unwrapT}ms`);
      log("DATA",`AES key: ${toHex(aesRawDec).slice(0,16)}... [256-bit]`);setProg(30);await sleep(60);

      const aesKDec=await importAES(aesRawDec);
      log("INFO","AES-256-GCM decryption...");
      const t2=performance.now();
      const plain=await aesDec(aesKDec,iv,ct);
      const decT=(performance.now()-t2).toFixed(0);
      log("OK",`Decryption complete in ${decT}ms`);setProg(55);await sleep(60);

      log("INFO","Verifying HMAC-SHA256 integrity tag...");
      const hmacOk=await hmacVerify(aesRawDec,hmacSig,plain);
      log(hmacOk?"OK":"ERR",`HMAC verification: ${hmacOk?"PASSED ✓":"FAILED ✗"}`);setProg(72);await sleep(60);

      log("INFO","Recomputing SHA-256 fingerprint...");
      const t3=performance.now();
      const reHash=await sha256(plain);
      const vT=(performance.now()-t3).toFixed(0);
      const match=reHash===fileHash;
      log(match?"OK":"ERR",`SHA-256 match: ${match?"VERIFIED ✓":"MISMATCH ✗"} (${vT}ms)`);setProg(90);await sleep(60);

      const total=(performance.now()-T).toFixed(0);
      log("OK",`✓ Pipeline complete in ${total}ms — Integrity: ${match&&hmacOk?"VERIFIED":"COMPROMISED"}`);setProg(100);
      setResult({match,hmacOk,text:new TextDecoder().decode(plain),hash:reHash,unwrapT,decT,total});
    }catch(e){log("ERR",e.message)}
    setRunning(false);
  };

  return(
    <div>
      <div className="page-header">
        <div className="page-title">🔓 Decrypt & Verify</div>
        <div className="page-sub">Phase 3: RSA unwrap → AES-GCM decrypt → HMAC verify → SHA-256 integrity check</div>
      </div>
      <div className="card">
        <div className="card-hd"><div className="chip purple">🔓</div><div><div className="card-title">Decryption Pipeline</div><div className="card-desc">Unwrap session key → decrypt → dual integrity verification</div></div></div>
        <div className="status info" style={{marginBottom:16}}> In deployment, receiver loads the encrypted envelope. Then receiver device checks integrity and authenticity and decrypts the file.</div>
        <div className="flex-end">
          <button className="btn btn-ghost" onClick={setup} disabled={running}> Generate Envelope</button>
          <button className="btn btn-c" onClick={run} disabled={!ready||running}>{running?"⏳ Decrypting...":"🔓 Decrypt & Verify"}</button>
        </div>
      </div>
      {logs.length>0&&(
        <div className="card">
          <div className="card-hd"><div className="chip amber">⚙️</div><div><div className="card-title">Decryption Log</div><div className="card-desc">Step-by-step decryption execution</div></div></div>
          {prog>0&&<Prog val={prog} color="g" label="RSA Unwrap → AES Decrypt → HMAC → SHA-256"/>}
          <Terminal logs={logs} running={running}/>
        </div>
      )}
      {result&&(
        <div className="card">
          <div className="card-hd"><div className="chip green">✅</div><div><div className="card-title">Result</div><div className="card-desc">Integrity-verified plaintext</div></div></div>
          <div className={`status ${result.match&&result.hmacOk?"ok":"err"}`} style={{marginBottom:14}}>
            {result.match&&result.hmacOk?"✓ INTEGRITY VERIFIED — SHA-256 + HMAC both pass":"✗ INTEGRITY FAILURE — tampering detected"}
          </div>
          <div className="field"><label>Recovered Plaintext</label><textarea className="inp" rows={9} readOnly value={result.text}/></div>
          <div className="grid2">
            <div className="obox"><div className="olbl">SHA-256 (recomputed)</div><div className="oval purple">{result.hash.slice(0,32)}<br/>{result.hash.slice(32)}</div></div>
            <div className="obox"><div className="olbl">Verification Summary</div>
              <div style={{fontFamily:"var(--mono)",fontSize:11,lineHeight:2}}>
                <div><span style={{color:"var(--muted)"}}>HMAC-SHA256: </span><span style={{color:result.hmacOk?"var(--green)":"var(--red)"}}>{result.hmacOk?"✓ PASS":"✗ FAIL"}</span></div>
                <div><span style={{color:"var(--muted)"}}>SHA-256 hash: </span><span style={{color:result.match?"var(--green)":"var(--red)"}}>{result.match?"✓ MATCH":"✗ MISMATCH"}</span></div>
                <div><span style={{color:"var(--muted)"}}>RSA unwrap: </span><span style={{color:"var(--green)"}}>✓ {result.unwrapT}ms</span></div>
                <div><span style={{color:"var(--muted)"}}>Total time: </span><span style={{color:"var(--cyan)"}}>{result.total}ms</span></div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}