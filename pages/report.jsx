import React from "react";

import "../CSS/card.css";
import "../CSS/report.css";

export default function Report() {
    return(
        <div>
      <div className="page-header">
        <div className="page-title">📄 Project Overview</div>
        <div className="page-sub">Complete academic submission....</div>
      </div>

      <div className="cover">
        <div className="cover-logo">🔐</div>
        <div className="cover-title">Hybrid Cryptographic Protocol</div>
        <div className="cover-title" style={{fontSize:20}}>for Secure File Transfer</div>
        <div className="cover-sub" style={{marginTop:8}}>with Attack Mitigation & Performance Analysis</div>
        <div style={{height:1,background:"var(--border)",margin:"24px auto",maxWidth:300}}/>
        <div className="cover-meta">
          {[["Student","Farhad Hasan Shourov"],["Department","EEE, RU"],["Project Type","Final Year Project"],["Version","v1.0 — 2025"]].map(([k,v])=>(
            <div key={k} className="cover-field">
              <div className="cover-field-lbl">{k}</div>
              <div className="cover-field-val">{v}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="report-section">
          <div className="report-h2">1. Introduction</div>
          <div className="report-p">With the rapid growth of digital communication, secure file transfer has become a critical requirement in modern computing systems. Sensitive data transmitted over networks is vulnerable to interception, tampering, replay attacks, and unauthorized access. Traditional encryption techniques alone are insufficient to ensure complete security.</div>
          <div className="report-p">This project designs and implements a <strong>Hybrid Cryptographic Protocol</strong> that integrates symmetric encryption (AES-256-GCM), asymmetric encryption (RSA-OAEP), message authentication (HMAC-SHA256), and integrity verification (SHA-256) into a unified secure file transfer system — following the architecture of real-world protocols such as TLS 1.3.</div>
        </div>

        <div className="report-section">
          <div className="report-h2">2. Objectives</div>
          <ul className="report-ul">
            <li>Design a secure file transfer system using hybrid cryptography (symmetric + asymmetric)</li>
            <li>Implement AES-256-GCM for authenticated bulk file encryption</li>
            <li>Implement RSA-2048/3072-OAEP for secure session key wrapping</li>
            <li>Ensure data integrity using HMAC-SHA256 (keyed) and SHA-256 (fingerprint)</li>
            <li>Simulate real-world attacks: MITM, Replay, Data Tampering, ECB Pattern Leakage</li>
            <li>Evaluate and compare performance: AES-GCM vs AES-CBC, RSA key sizes</li>
            <li>Demonstrate practical understanding of the CIA security triad</li>
          </ul>
        </div>

        <div className="report-section">
          <div className="report-h2">3. Literature Review</div>
          <div className="report-p">Hybrid cryptographic systems are the foundation of modern secure communication protocols including TLS 1.3, PGP, and SSH. The combination of symmetric and asymmetric cryptography solves the fundamental key distribution problem while maintaining performance.</div>
          <div className="report-h3">3.1 AES (Advanced Encryption Standard)</div>
          <div className="report-p">Standardized by NIST in 2001 (FIPS 197), AES is the global standard for symmetric encryption. AES-256 provides 256-bit key strength (2²⁵⁶ brute-force space). GCM (Galois/Counter Mode) extends AES with authenticated encryption, providing both confidentiality and integrity in a single pass, eliminating the need for separate MAC computation and removing padding oracle vulnerabilities present in CBC mode.</div>
          <div className="report-h3">3.2 RSA (Rivest-Shamir-Adleman)</div>
          <div className="report-p">RSA is the most widely deployed asymmetric algorithm. Its security relies on the integer factorization problem. OAEP (Optimal Asymmetric Encryption Padding) padding scheme is required over PKCS#1 v1.5 to prevent the Bleichenbacher (1998) padding oracle attack. NIST SP 800-131A recommends ≥ 3072-bit keys for security beyond 2030.</div>
          <div className="report-h3">3.3 HMAC-SHA256</div>
          <div className="report-p">HMAC (RFC 2104) provides message authentication using a cryptographic hash function combined with a secret key. Unlike plain SHA-256, HMAC is resistant to length-extension attacks and requires knowledge of the shared secret key for verification, providing both integrity and authentication.</div>
        </div>

        <div className="report-section">
          <div className="report-h2">4. Methodology</div>
          <div className="report-h3">4.1 Phase 1 — Secure Handshake</div>
          <ul className="report-ul">
            <li>Server generates RSA key pair and distributes public key with certificate</li>
            <li>Client verifies server certificate authenticity</li>
            <li>Client generates a cryptographically random 256-bit AES session key</li>
            <li>Session key is encrypted using RSA-OAEP with server's public key</li>
          </ul>
          <div className="report-h3">4.2 Phase 2 — File Encryption & Transmission</div>
          <ul className="report-ul">
            <li>File is encrypted using AES-256-GCM with a random 96-bit IV (nonce)</li>
            <li>HMAC-SHA256 is computed over plaintext using AES session key</li>
            <li>SHA-256 fingerprint of original file is computed</li>
            <li>Envelope {"{ciphertext, IV, wrapped_key, HMAC, SHA256}"} transmitted</li>
          </ul>
          <div className="report-h3">4.3 Phase 3 — Decryption & Verification</div>
          <ul className="report-ul">
            <li>Server uses RSA private key to unwrap the AES session key</li>
            <li>AES-256-GCM decrypts the file (GCM tag verified automatically)</li>
            <li>HMAC-SHA256 is recomputed and compared against transmitted tag</li>
            <li>SHA-256 fingerprint recomputed and verified — integrity confirmed</li>
          </ul>
        </div>

        <div className="report-section">
          <div className="report-h2">5. Attack Simulations & Mitigations</div>
          <table className="report-table">
            <thead><tr><th>Attack</th><th>Method</th><th>Mitigation</th><th>Result</th></tr></thead>
            <tbody>
              {[
                ["Man-in-the-Middle","Rogue RSA key injection","Certificate pinning + digital signature","Blocked ✓"],
                ["Replay Attack","Captured packet retransmission","IV uniqueness registry + timestamps","Blocked ✓"],
                ["Data Tampering","Ciphertext bit-flip","AES-GCM auth tag + HMAC-SHA256","Blocked ✓"],
                ["ECB Pattern Leakage","Identical block detection","GCM mode with random IV","Prevented ✓"],
              ].map(r=>(
                <tr key={r[0]}>{r.map((c,i)=><td key={i} style={{color:i===3?"var(--green)":undefined}}>{c}</td>)}</tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="report-section">
          <div className="report-h2">6. Technologies Used</div>
          <table className="report-table">
            <thead><tr><th>Component</th><th>Technology</th><th>Purpose</th></tr></thead>
            <tbody>
              {[
                ["Frontend","React + JSX","Interactive UI, real-time demos"],
                ["Cryptography","Web Crypto API (W3C Standard)","All cryptographic operations"],
                ["Symmetric Enc.","AES-256-GCM","File encryption + authentication"],
                ["Asymmetric Enc.","RSA-OAEP (2048/3072/4096)","Session key wrapping"],
                ["Integrity","HMAC-SHA256 + SHA-256","Message auth + fingerprint"],
                ["Environment","Browser (cross-platform)","Windows / Linux / macOS / Android"],
              ].map(r=><tr key={r[0]}>{r.map((c,i)=><td key={i}>{c}</td>)}</tr>)}
            </tbody>
          </table>
        </div>

        <div className="report-section">
          <div className="report-h2">7. Expected Outcomes</div>
          <ul className="report-ul">
            <li>Fully functional hybrid cryptographic file transfer system with live demos</li>
            <li>Demonstration of 4 real-world attack types with active mitigations</li>
            <li>Quantitative performance comparison: AES-GCM vs CBC, RSA-2048 vs 3072 vs 4096</li>
            <li>Practical implementation of CIA triad: Confidentiality, Integrity, Authentication</li>
            <li>Academic-grade documentation suitable for final year submission</li>
          </ul>
        </div>
      </div>
    </div>
  );
}