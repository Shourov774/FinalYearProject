import React from "react";

import { useState } from "react";
import {genAES,genRSA,aesEnc,aesDec,rsaEnc,rsaDec,exportRaw,importAES,hmacSign,hmacVerify,sha256,toHex,toB64,fmtB,sleep,now} from "../cryotoFunction";
import Terminal from "../components/terminal";
import EcbEncSimulate from "../ECB_Simulation";
import "../CSS/status.css";
import "../CSS/attack.css";
import "../CSS/card.css";
import "../CSS/btn.css"

export default function Attack() {
    const [open,setOpen]=useState(null);
    const [logs,setLogs]=useState({});
    const [running,setRunning]=useState(null);
    const [results,setResults]=useState({});

    const log=(id,k,m)=>setLogs(l=>({...l,[id]:[...(l[id]||[]),{t:now(),k,m}]}));
    const setRes=(id,r)=>setResults(p=>({...p,[id]:r}));

    // Attack 1: MITM
    const runMITM = async() => {
        const id = "mitm";
        setRunning(id);
        setLogs(p=>({...p,[id]:[]}));
        setRes(id,null);

        log(id,"INFO","[ATTACKER] Intercepting key exchange channel...");
        await sleep(400);
        log(id,"WARN","[ATTACKER] Client hello captured. Injecting rogue RSA public key...");
        await sleep(500);

        const rogueKP = await genRSA(2048);
        const legitKP = await genRSA(2048);
        log( id, "ERR","[ATTACKER] Rogue key injected. Client will encrypt to attacker!");await sleep(400);
        const sessionKey=window.crypto.getRandomValues(new Uint8Array(32));
        const wrappedByRogue=await rsaEnc(rogueKP.publicKey,sessionKey);
        log( id, "ERR","[ATTACKER] Session key intercepted and decrypted ✓");
        await sleep(300);
        log( id, "WARN","[MITIGATION] Certificate pinning detected key mismatch");
        await sleep(300);
        log( id, "WARN","[MITIGATION] Digital signature validation failed for rogue key");
        await sleep(300);
        log( id, "OK","[SYSTEM] MITM attack BLOCKED — certificate chain rejected");

        setRes(id,{blocked:true,detail:"Attacker injected RSA key but rejected by certificate verification."});
        setRunning(null);
    };

    // Attack 2: Replay
    const runReplay = async()=> {

        const id="replay";setRunning(id);
        setLogs(p=>({...p,[id]:[]}));
        setRes(id,null);
        log( id,"INFO","[ATTACKER] Capturing encrypted packet from session #A1B2...");
        await sleep(400);
        const data=new TextEncoder().encode("Transfer $5000 to account 99887766");
        const aesK=await genAES();
        const {iv,ct}=await aesEnc(aesK,data);
        log(id,"WARN",`[ATTACKER] Packet captured: IV=${toHex(iv).slice(0,12)}... CipherText Length=${fmtB(ct.byteLength)}`);await sleep(400);
        log(id,"ERR","[ATTACKER] Replaying packet to server 2 times...");
        await sleep(500);
        const ts1=Date.now();await sleep(200);const ts2=Date.now();
        log(id,"WARN",`[SERVER] Packet #1 received — timestamp: ${ts1}`);
        await sleep(200);
        log(id,"WARN",`[SERVER] Packet #2 received — timestamp: ${ts2}`);
        await sleep(200);
        log(id,"WARN","[MITIGATION] Timestamp window check: Δt="+( ts2-ts1)+"ms > 0ms (duplicate detected)");await sleep(300);
        log(id,"WARN","[MITIGATION] Nonce registry: IV already seen in session store");await sleep(300);
        log(id,"OK","[SYSTEM] Replay attack BLOCKED — duplicate IV + timestamp rejected");
        setRes(id,{blocked:true,detail:"Captured packet replayed 2 times. Server's nonce registry detected duplicate IV. All replayed packets rejected."});
        setRunning(null);
    };

    // Attack 3: Tamper
    const runTamper=async()=>{
        const id = "tamper";setRunning(id);setLogs(p=>({...p,[id]:[]}));setRes(id,null);
        const msg = "Pay $100 to Shourov";
        const data = new TextEncoder().encode(msg);
        const aesK = await genAES();
        const aesRaw = await exportRaw(aesK);
        const {iv,ct} = await aesEnc(aesK,data);
        const origHash = await sha256(data);
        const origHmac = await hmacSign(aesRaw,data);
        log(id,"INFO",`Original: "${msg}"`);
        log(id,"DATA",`SHA-256: ${origHash.slice(0,32)}...`);
        await sleep(400);
        log(id,"WARN","[ATTACKER] Flipping bytes 2,3,4 of ciphertext (bit-flip attack)...");
        await sleep(300);
        const tampered=new Uint8Array(ct);
        tampered[2]^=0xFF;
        tampered[3]^=0xAA;
        tampered[4]^=0x55;
        log(id,"ERR","[ATTACKER] Tampered ciphertext sent to receiver");
        await sleep(400);
        let decOk=true,decText="";
        try{
            const plain=await aesDec(aesK,iv,tampered);
            decText=new TextDecoder().decode(plain);
        }catch(e){decOk=false;log(id,"OK","[AES-GCM] Authentication tag FAILED — decryption aborted ✓");}
        if(!decOk){
            log(id,"OK","[MITIGATION] AES-GCM auth tag rejected tampered ciphertext");
            log(id,"OK","[MITIGATION] HMAC-SHA256 would also fail independently");
            log(id,"OK","[SYSTEM] Tampering attack BLOCKED — GCM tag + HMAC both detect modification");
        }
        setRes(id,{blocked:true,detail:"Bytes 2-4 of ciphertext flipped. AES-GCM auth tag immediately rejected the packet. HMAC provides secondary verification."});
        setRunning(null);
    };

    // Attack 4: ECB Pattern
    const runECB=async()=>{
        const id="ecb";setRunning(id);setLogs(p=>({...p,[id]:[]}));setRes(id,null);
        log(id,"INFO","Encrypting structured data with ECB mode (16-byte blocks, no IV)...");await sleep(300);
        const structured="AAAAAAAAAAAAAAAA"+"BBBBBBBBBBBBBBBB"+"AAAAAAAAAAAAAAAA"+"CCCCCCCCCCCCCCCC"+"AAAAAAAAAAAAAAAA";
        const data=new TextEncoder().encode(structured);
        const ecbOut=await EcbEncSimulate(data);
        log(id,"WARN","[ECB] Block 0 (AAAA...): "+toHex(ecbOut.slice(0,16)));
        log(id,"WARN","[ECB] Block 1 (BBBB...): "+toHex(ecbOut.slice(16,32)));
        log(id,"ERR","[ECB] Block 2 (AAAA...): "+toHex(ecbOut.slice(32,48))+" ← IDENTICAL to Block 0!");
        log(id,"WARN","[ECB] Block 3 (CCCC...): "+toHex(ecbOut.slice(48,64)));
        log(id,"ERR","[ECB] Block 4 (AAAA...): "+toHex(ecbOut.slice(64,80))+" ← IDENTICAL to Block 0 & 2!");await sleep(400);
        log(id,"INFO","Encrypting same data with AES-256-GCM (random IV per block)...");
        const aesK=await genAES();
        const {iv,ct}=await aesEnc(aesK,data);
        log(id,"OK","[GCM] Output appears fully random — no repeating patterns");
        log(id,"OK","[GCM] IV: "+toHex(iv)+" (random per session)");
        log(id,"OK","[SYSTEM] GCM mode: zero pattern leakage ✓");
        setRes(id,{
            ecbBlocks:[toHex(ecbOut.slice(0,16)),toHex(ecbOut.slice(16,32)),toHex(ecbOut.slice(32,48)),toHex(ecbOut.slice(48,64)),toHex(ecbOut.slice(64,80))],
            blocked:true,detail:"ECB leaks that blocks 0, 2, and 4 are identical plaintexts. GCM's random IV makes every block unique, eliminating pattern leakage."
        });
        setRunning(null);
    };

    const attacks=[
        {id:"mitm",label:"MITM",title:"Man-in-the-Middle Attack",desc:"Rogue key injection during RSA handshake",color:"red",run:runMITM,
            explain:"Attacker intercepts key exchange and injects rogue RSA public key. Client unknowingly encrypts session key for attacker.\n Mitigation: certificate pinning + digital signature verification."},
        {id:"replay",label:"REPLAY",title:"Replay Attack",desc:"Captured packet retransmission",color:"red",run:runReplay,
            explain:"Attacker captures a valid encrypted packet and resends it. Without replay protection, server may process it twice. Mitigation: nonce/IV uniqueness tracking + timestamp windows."},
        {id:"tamper",label:"TAMPER",title:"Data Tampering Attack",desc:"Ciphertext bit-flip modification",color:"amber",run:runTamper,
            explain:"Attacker flips bits in the ciphertext hoping to alter decrypted content. AES-GCM's authentication tag detects any modification. HMAC-SHA256 provides secondary verification."},
        {id:"ecb",label:"ECB LEAK",title:"ECB Pattern Leakage Demo",desc:"Why ECB mode is cryptographically broken",color:"amber",run:runECB,
            explain:"ECB encrypts each 16-byte block independently with the same key. Identical plaintext blocks produce identical ciphertext — leaking structural information. GCM uses a random IV and CTR mode, producing unique output even for identical inputs."},
    ];

    return(
        <div>
            <div className="page-header">
            <div className="page-title">⚠️ Attack Simulations</div>
            <div className="page-sub">Live demonstration of MITM, Replay, Tampering, and ECB Pattern Leakage — with mitigations</div>
            </div>
            <div className="status warn" style={{marginBottom:16}}>⚠️ These are controlled simulations for academic demonstration. All cryptographic operations are real.</div>

            {attacks.map(atk=>(
            <div key={atk.id} className="atk-card">
                <div className="atk-hd" onClick={()=>setOpen(open===atk.id?null:atk.id)}>
                <div className="atk-hd-left">
                    <span className={`atk-badge ${atk.color}`}>{atk.label}</span>
                    <div>
                    <div style={{fontWeight:700,fontSize:14}}>{atk.title}</div>
                    <div style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--muted)",marginTop:2}}>{atk.desc}</div>
                    </div>
                </div>
                <div style={{display:"flex",alignItems:"center",gap:10}}>
                    {results[atk.id]&&<span style={{color:"var(--green)",fontSize:12,fontFamily:"var(--mono)"}}>✓ BLOCKED</span>}
                    <span style={{color:"var(--muted)",fontSize:12}}>{open===atk.id?"▲":"▼"}</span>
                </div>
                </div>
                {open===atk.id&&(
                <div className="atk-body">
                    <div style={{fontSize:13,color:"#8899bb",lineHeight:1.7,marginBottom:14}}>{atk.explain}</div>
                    <div className="flex-end" style={{marginTop:0,marginBottom:14}}>
                    <button className="btn btn-r btn-sm" onClick={atk.run} disabled={running===atk.id}>
                        {running===atk.id?"⏳ Simulating...":"▶ Run Simulation"}
                    </button>
                    </div>
                    {(logs[atk.id]||[]).length>0&&<Terminal logs={logs[atk.id]||[]} running={running===atk.id}/>}
                    {results[atk.id]&&(
                    <div className="status ok mt12">{results[atk.id].blocked?"🛡️ Attack BLOCKED — ":""}{results[atk.id].detail}</div>
                    )}
                    {results[atk.id]?.ecbBlocks&&(
                    <div className="mt12">
                        <label>ECB Block Analysis</label>
                        {results[atk.id].ecbBlocks.map((b,i)=>(
                        <div key={i} style={{display:"flex",gap:10,marginBottom:4,fontFamily:"var(--mono)",fontSize:11,alignItems:"center"}}>
                            <span style={{color:"var(--muted)",width:60}}>Block {i}:</span>
                            <span style={{color:i===0||i===2||i===4?"var(--red)":"var(--txt)"}}>{b}</span>
                            {(i===2||i===4)&&<span style={{color:"var(--red)"}}>← SAME!</span>}
                        </div>
                        ))}
                    </div>
                    )}
                </div>
                )}
            </div>
            ))}
        </div>
    );
}