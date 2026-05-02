import React from "react";
import { useState,useRef } from "react";

import "../CSS/status.css"
import "../CSS/architecture.css"
import "../CSS/card.css"

export default function Architecture() {
  return(
    <div>
      <div className="page-header">
        <div className="page-title">📐 System Architecture</div>
        <div className="page-sub">Hybrid cryptographic protocol</div>
      </div>

      <div className="card">
        <div className="card-hd"><div className="chip cyan">🔐</div><div><div className="card-title">Encryption Phase Flow</div></div></div>
        <div style={{fontSize:11,fontFamily:"var(--mono)",color:"var(--muted)",marginBottom:8}}>SENDER (CLIENT)</div>
        <div className="flow">
          <div className="fbox">📄 Plaintext</div><span className="farr">→</span>
          <div className="fbox g">AES-256-GCM</div><span className="farr">→</span>
          <div className="fbox a">🔐 Ciphertext + GCM Tag</div>
        </div>
        <div className="flow">
          <div className="fbox">🔑 AES Session Key</div><span className="farr">→</span>
          <div className="fbox p">RSA-OAEP (Public Key)</div><span className="farr">→</span>
          <div className="fbox a">🔒 Wrapped Key</div>
        </div>
        <div className="flow">
          <div className="fbox">📄 Plaintext</div><span className="farr">→</span>
          <div className="fbox g">HMAC-SHA256</div><span className="farr">→</span>
          <div className="fbox g">🏷️ Auth Tag</div>
        </div>
        <div className="flow">
          <div className="fbox">📄 Plaintext</div><span className="farr">→</span>
          <div className="fbox g">SHA-256</div><span className="farr">→</span>
          <div className="fbox g">🔍 Fingerprint</div>
        </div>
        <div className="div"/>
        <div style={{fontSize:11,fontFamily:"var(--mono)",color:"var(--muted)",marginBottom:8}}>RECEIVER (SERVER)</div>
        <div className="flow">
          <div className="fbox a">🔒 Wrapped Key</div><span className="farr">→</span>
          <div className="fbox p">RSA-OAEP (Private Key)</div><span className="farr">→</span>
          <div className="fbox">🔑 AES Key</div><span className="farr">→</span>
          <div className="fbox g">AES-256-GCM</div><span className="farr">→</span>
          <div className="fbox g">📄 Plaintext</div>
        </div>
        <div className="flow">
          <div className="fbox">📄 Plaintext</div><span className="farr">→</span>
          <div className="fbox g">HMAC-SHA256</div><span className="farr">→</span>
          <div className="fbox">Compare</div><span className="farr">→</span>
          <div className="fbox g">✓ Auth Verified</div>
        </div>
        <div className="flow">
          <div className="fbox">📄 Plaintext</div><span className="farr">→</span>
          <div className="fbox g">SHA-256</div><span className="farr">→</span>
          <div className="fbox">Compare</div><span className="farr">→</span>
          <div className="fbox g">✓ Integrity Verified</div>
        </div>
      </div>

      <div className="grid2">
        {[
          {title:"AES-256-GCM",color:"cyan",rows:[["Algorithm","AES (Rijndael)"],["Key Length","256 bits"],["Mode","Galois/Counter Mode"],["IV","96-bit random nonce"],["Auth Tag","128-bit GCM tag"],["vs CBC","No padding oracle risk"],["Standard","NIST FIPS 197"]]},
          {title:"RSA-OAEP",color:"purple",rows:[["Key Size","2048 / 3072 / 4096"],["Padding","OAEP (SHA-256 hash)"],["Usage","Key wrapping only"],["NIST 2030+","≥ 3072 bits"],["vs PKCS#1 v1.5","No Bleichenbacher"],["Standard","PKCS #1 v2.2"]]},
          {title:"HMAC-SHA256",color:"green",rows:[["Algorithm","HMAC (RFC 2104)"],["Hash","SHA-256"],["Output","256-bit MAC"],["Key","AES session key"],["Purpose","Message integrity"],["vs plain hash","Requires secret key"],["Attack resist","Length extension safe"]]},
          {title:"SHA-256",color:"amber",rows:[["Output","256-bit digest"],["Role","File fingerprint"],["vs GCM tag","End-to-end integrity"],["vs HMAC","No key required"],["Collision","2¹²⁸ resistance"],["Standard","FIPS 180-4"]]},
        ].map(({title,color,rows})=>(
          <div key={title} className="card" style={{marginBottom:0}}>
            <div className="card-hd"><div className="card-title" style={{color:`var(--${color})`}}>{title}</div></div>
            <table className="itbl">
              <tbody>{rows.map(([k,v])=>(
                <tr key={k}><td style={{color:"var(--muted)"}}>{k}</td><td style={{color:`var(--${color})`}}>{v}</td></tr>
              ))}</tbody>
            </table>
          </div>
        ))}
      </div>

      <div className="card mt16">
        <div className="card-hd"><div className="chip amber">🛡️</div><div><div className="card-title">Security Model</div><div className="card-desc">CIA triad + threat mitigation map</div></div></div>
        <table className="itbl">
          <thead><tr><th>Property</th><th>Mechanism</th><th>Attack Mitigated</th><th>Status</th></tr></thead>
          <tbody>
            {[
              ["Confidentiality","AES-256-GCM","Eavesdropping, MITM","✓ Enforced"],
              ["Integrity","HMAC-SHA256 + GCM tag","Data tampering, bit-flip","✓ Dual-layer"],
              ["Authentication","RSA certificate + HMAC","Impersonation, MITM","✓ Enforced"],
              ["Non-repudiation","Digital signatures (RSA-PSS)","Deniability","✓ Supported"],
              ["Forward Security","New session key per file","Session compromise","✓ Per-session"],
              ["Replay Prevention","IV uniqueness + timestamps","Replay attacks","✓ Enforced"],
              ["Pattern Hiding","GCM mode (not ECB)","Traffic analysis","✓ Enforced"],
            ].map(([p,m,a,s])=>(
              <tr key={p}>
                <td style={{color:"var(--txt)",fontWeight:600}}>{p}</td>
                <td style={{color:"var(--cyan)"}}>{m}</td>
                <td style={{color:"var(--muted)"}}>{a}</td>
                <td style={{color:"var(--green)"}}>{s}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}