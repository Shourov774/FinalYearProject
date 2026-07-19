import React, { useRef, useState } from "react";

import DropZone from "../components/dropZone";
import Terminal from "../components/terminal";
import {
  genAES,
  genRSA,
  aesEnc,
  rsaEnc,
  exportRaw,
  hmacSign,
  sha256,
  toHex,
  fmtB,
  sleep,
  now,
  readFile,
} from "../cryotoFunction";
import Prog from "../components/progs";
import "../CSS/status.css";
import "../CSS/card.css";
import "../CSS/btn.css";

const bytesToBase64 = (value) => {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  const chunkSize = 0x8000;
  let binary = "";

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }

  return window.btoa(binary);
};

const downloadJson = (data, fileName) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");

  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
};

const copyToClipboard = async (text) => {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  document.execCommand("copy");
  textarea.remove();
};

export default function Encrypt() {
  const [inputMode, setInputMode] = useState("file");
  const [file, setFile] = useState(null);
  const [textInput, setTextInput] = useState("");
  const [rsaBits, setRsaBits] = useState("2048");
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [prog, setProg] = useState(0);
  const [result, setResult] = useState(null);
  const [copied, setCopied] = useState("");
  const store = useRef({});

  const textBytes = new TextEncoder().encode(textInput).byteLength;
  const hasInput = inputMode === "file" ? Boolean(file) : textInput.trim().length > 0;

  const log = (k, m) => {
    setLogs((l) => [...l, { t: now(), k, m }]);
  };

  const resetOutput = () => {
    setLogs([]);
    setProg(0);
    setResult(null);
    setCopied("");
    store.current = {};
  };

  const changeInputMode = (mode) => {
    if (running || mode === inputMode) return;
    setInputMode(mode);
    resetOutput();
  };

  const copyValue = async (label, value) => {
    try {
      await copyToClipboard(value);
      setCopied(label);
      log("OK", `${label} copied to clipboard`);
      window.setTimeout(() => setCopied(""), 1600);
    } catch (error) {
      log("ERR", `Could not copy ${label}: ${error.message}`);
    }
  };

  const run = async () => {
    if (!hasInput) return;

    setRunning(true);
    setLogs([]);
    setProg(0);
    setResult(null);
    setCopied("");

    try {
      const T = performance.now();
      let sourceBytes;
      let payload;

      if (inputMode === "file") {
        sourceBytes = await readFile(file);
        payload = {
          kind: "file",
          name: file.name,
          type: file.type || "application/octet-stream",
          size: sourceBytes.byteLength,
          lastModified: file.lastModified,
        };
        log("INFO", `Loaded file: ${file.name} (${fmtB(sourceBytes.byteLength)})`);
      } else {
        sourceBytes = new TextEncoder().encode(textInput);
        payload = {
          kind: "text",
          name: "encrypted-text.txt",
          type: "text/plain;charset=utf-8",
          size: sourceBytes.byteLength,
          encoding: "utf-8",
          characters: textInput.length,
          lastModified: null,
        };
        log(
          "INFO",
          `Loaded text: ${textInput.length} characters (${fmtB(sourceBytes.byteLength)})`,
        );
      }

      await sleep(100);

      log("INFO", `Generating RSA-${rsaBits} key pair (OAEP / SHA-256)...`);
      const t1 = performance.now();
      const rsaKP = await genRSA(Number(rsaBits));
      const rsaT = (performance.now() - t1).toFixed(0);
      log("OK", `RSA key pair ready in ${rsaT}ms`);
      setProg(15);

      log("INFO", "Generating AES-256 session key...");
      const aesK = await genAES();
      const aesRaw = await exportRaw(aesK);
      log("OK", "AES-256 session key generated");
      setProg(25);
      await sleep(60);

      log("INFO", "Computing SHA-256 fingerprint...");
      const t2 = performance.now();
      const sourceHash = await sha256(sourceBytes);
      const hashT = (performance.now() - t2).toFixed(0);
      log("DATA", `SHA-256: ${sourceHash}`);
      setProg(38);

      log("INFO", "Computing HMAC-SHA256 for integrity...");
      const hmacSig = await hmacSign(aesRaw, sourceBytes);
      log("DATA", `HMAC: ${toHex(hmacSig).slice(0, 32)}...`);
      setProg(50);
      await sleep(60);

      log(
        "INFO",
        inputMode === "file"
          ? "Encrypting file with AES-256-GCM..."
          : "Encrypting text with AES-256-GCM...",
      );
      const t3 = performance.now();
      const { iv, ct } = await aesEnc(aesK, sourceBytes);
      const aesT = (performance.now() - t3).toFixed(0);
      log(
        "OK",
        `AES-GCM done in ${aesT}ms | IV: ${toHex(iv)} | CT: ${fmtB(ct.byteLength)}`,
      );
      setProg(68);
      await sleep(60);

      log("INFO", `Wrapping AES key with RSA-${rsaBits} public key (OAEP)...`);
      const t4 = performance.now();
      const wrapped = await rsaEnc(rsaKP.publicKey, aesRaw);
      const wrapT = (performance.now() - t4).toFixed(0);
      log("OK", `Key wrapped in ${wrapT}ms`);
      setProg(82);
      await sleep(60);

      log("INFO", "Exporting receiver RSA keys for manual decryption demo...");
      const privateKeyPkcs8 = await window.crypto.subtle.exportKey(
        "pkcs8",
        rsaKP.privateKey,
      );
      const publicKeySpki = await window.crypto.subtle.exportKey(
        "spki",
        rsaKP.publicKey,
      );
      setProg(90);

      const ivB64 = bytesToBase64(iv);
      const ciphertextB64 = bytesToBase64(ct);
      const wrappedKeyB64 = bytesToBase64(wrapped);
      const hmacB64 = bytesToBase64(hmacSig);
      const privateKeyB64 = bytesToBase64(privateKeyPkcs8);
      const publicKeyB64 = bytesToBase64(publicKeySpki);

      const envelope = {
        schema: "hybrid-crypto-envelope",
        version: 2,
        createdAt: new Date().toISOString(),
        encoding: "base64",
        inputType: payload.kind,
        algorithms: {
          payloadEncryption: "AES-256-GCM",
          keyWrap: `RSA-${rsaBits}-OAEP`,
          oaepHash: "SHA-256",
          integrity: "HMAC-SHA256",
          fingerprint: "SHA-256",
        },
        payload,
        file: {
          name: payload.name,
          type: payload.type,
          size: payload.size,
          lastModified: payload.lastModified,
        },
        iv: ivB64,
        ciphertext: ciphertextB64,
        wrappedAesKey: wrappedKeyB64,
        sha256: sourceHash,
        hmac: hmacB64,
      };

      const receiverKey = {
        schema: "hybrid-crypto-receiver-key",
        version: 1,
        algorithm: "RSA-OAEP",
        hash: "SHA-256",
        modulusLength: Number(rsaBits),
        format: "pkcs8",
        privateKey: privateKeyB64,
        publicKeyFormat: "spki",
        publicKey: publicKeyB64,
      };

      const fullDemoPackage = {
        schema: "hybrid-crypto-full-demo-package",
        version: 2,
        warning:
          "Demo/testing only. In real deployment, never send the RSA private key with the encrypted envelope.",
        envelope,
        receiverKey,
      };

      const total = (performance.now() - T).toFixed(0);
      log("OK", `✓ Digital envelope sealed. Total: ${total}ms`);
      setProg(100);

      const outputName =
        inputMode === "file"
          ? file.name.replace(/[^a-zA-Z0-9._-]/g, "_") || "encrypted-file"
          : "encrypted-text";

      store.current = {
        rsaKP,
        iv,
        ct,
        wrapped,
        sourceHash,
        hmacSig,
        aesRaw,
        aesK,
        envelope,
        receiverKey,
      };

      setResult({
        inputKind: payload.kind,
        payloadName: payload.name,
        outputName,
        sourceHash,
        ivHex: toHex(iv),
        ivB64,
        ciphertextB64,
        wrappedKeyB64,
        hmacB64,
        privateKeyB64,
        publicKeyB64,
        ctSize: ct.byteLength,
        origSize: sourceBytes.byteLength,
        envelope,
        receiverKey,
        fullDemoPackage,
        envelopeJson: JSON.stringify(envelope, null, 2),
        receiverKeyJson: JSON.stringify(receiverKey, null, 2),
        fullDemoJson: JSON.stringify(fullDemoPackage, null, 2),
        perf: {
          rsa: rsaT,
          aes: aesT,
          wrap: wrapT,
          hash: hashT,
          total,
        },
      });
    } catch (e) {
      log("ERR", e.message || "Encryption failed");
    } finally {
      setRunning(false);
    }
  };

  const CopyButton = ({ label, value }) => (
    <button
      type="button"
      className="btn btn-ghost"
      style={{ padding: "7px 11px", fontSize: 11 }}
      onClick={() => copyValue(label, value)}
    >
      {copied === label ? "✓ Copied" : "📋 Copy"}
    </button>
  );

  const modeButtonStyle = (mode) => ({
    flex: 1,
    minHeight: 46,
    borderRadius: 9,
    border:
      inputMode === mode
        ? "1px solid var(--cyan)"
        : "1px solid var(--border, rgba(255,255,255,.14))",
    background:
      inputMode === mode
        ? "rgba(34, 211, 238, 0.12)"
        : "rgba(255,255,255,0.03)",
    color: inputMode === mode ? "var(--cyan)" : "var(--text, inherit)",
    fontWeight: 700,
    cursor: running ? "not-allowed" : "pointer",
    opacity: running ? 0.7 : 1,
  });

  return (
    <div>
      <div className="page-header">
        <div className="page-title">🔒 Encrypt File or Text</div>
        <div className="page-sub">
          Phase 1-2: Input → AES-256-GCM encryption → RSA-OAEP key wrapping →
          SHA-256 + HMAC integrity
        </div>
      </div>

      <div className="card">
        <div className="card-hd">
          <div className="chip cyan">🔑</div>
          <div>
            <div className="card-title">Input & Configuration</div>
            <div className="card-desc">
              Select a file or enter text, then choose cryptographic parameters
            </div>
          </div>
        </div>

        <div className="field">
          <label>Input Type</label>
          <div style={{ display: "flex", gap: 10, width: "100%" }}>
            <button
              type="button"
              style={modeButtonStyle("file")}
              onClick={() => changeInputMode("file")}
              disabled={running}
            >
              📁 File Upload
            </button>
            <button
              type="button"
              style={modeButtonStyle("text")}
              onClick={() => changeInputMode("text")}
              disabled={running}
            >
              📝 Text Input
            </button>
          </div>
        </div>

        {inputMode === "file" ? (
          <div className="field">
            <label>File to Encrypt</label>
            <DropZone
              file={file}
              onChange={(selectedFile) => {
                setFile(selectedFile);
                resetOutput();
              }}
            />
          </div>
        ) : (
          <div className="field">
            <label>Text to Encrypt</label>
            <textarea
              className="inp"
              rows={8}
              value={textInput}
              disabled={running}
              onChange={(event) => {
                setTextInput(event.target.value);
                resetOutput();
              }}
              placeholder="Write or paste Bangla, English, numbers or emoji here..."
              style={{ resize: "vertical", minHeight: 150 }}
            />
            <div
              className="status info"
              style={{ marginTop: 10, marginBottom: 0 }}
            >
              Characters: {textInput.length} &nbsp;•&nbsp; UTF-8 size: {fmtB(textBytes)}
            </div>
          </div>
        )}

        <div className="row2">
          <div className="field" style={{ marginBottom: 0 }}>
            <label>RSA Key Size</label>
            <select
              className="inp"
              value={rsaBits}
              disabled={running}
              onChange={(e) => {
                setRsaBits(e.target.value);
                resetOutput();
              }}
            >
              <option value="2048">RSA-2048 (Standard)</option>
              <option value="3072">RSA-3072 (NIST Post-2030)</option>
              <option value="4096">RSA-4096 (High Security)</option>
            </select>
          </div>

          <div className="field" style={{ marginBottom: 0 }}>
            <label>Symmetric Cipher</label>
            <select className="inp" disabled>
              <option>AES-256-GCM (Authenticated Encryption)</option>
            </select>
          </div>
        </div>
        <div className="flex-end">
          <button
            className="btn btn-c"
            onClick={run}
            disabled={!hasInput || running}
          >
            {running
              ? "⏳ Encrypting..."
              : inputMode === "file"
                ? "🔒 Encrypt File"
                : "🔒 Encrypt Text"}
          </button>
        </div>
      </div>

      {logs.length > 0 && (
        <div className="card">
          <div className="card-hd">
            <div className="chip amber">⚙️</div>
            <div>
              <div className="card-title">Execution Log</div>
              <div className="card-desc">
                Real cryptographic operations via Web Crypto API
              </div>
            </div>
          </div>

          {prog > 0 && (
            <Prog
              val={prog}
              color="c"
              label="AES-256-GCM Encryption Pipeline"
            />
          )}
          <Terminal logs={logs} running={running} />
        </div>
      )}

      {result && (
        <>
          <div className="card">
            <div className="card-hd">
              <div className="chip green">✅</div>
              <div>
                <div className="card-title">Encrypted Envelope</div>
                <div className="card-desc">
                  Encrypted {result.inputKind} — ready for secure transmission
                </div>
              </div>
            </div>

            <div className="status ok mt8" style={{ marginBottom: 14 }}>
              ✓ Digital envelope sealed — AES-GCM + HMAC + SHA-256
            </div>

            <div className="grid2">
              <div className="obox">
                <div className="olbl">SHA-256 Fingerprint</div>
                <div className="oval purple">
                  {result.sourceHash.slice(0, 32)}
                  <br />
                  {result.sourceHash.slice(32)}
                </div>
              </div>

              <div className="obox">
                <div className="olbl">AES-GCM IV (96-bit nonce)</div>
                <div className="oval cyan">{result.ivHex}</div>
              </div>

              <div className="obox">
                <div className="olbl">RSA-Wrapped AES Session Key</div>
                <div className="oval amber">
                  {result.wrappedKeyB64.slice(0, 72)}...
                </div>
              </div>

              <div className="obox">
                <div className="olbl">Ciphertext Size</div>
                <div className="oval green">
                  {fmtB(result.ctSize)}{" "}
                  <span style={{ color: "var(--muted)" }}>
                    ← Original: {fmtB(result.origSize)}
                  </span>
                </div>
              </div>
              <div className="obox">
                <div className="olbl">Cipher Text (256-bit)</div>
                <div className="oval green">{result.ciphertextB64.slice( 0 , 256 ) + "..."}</div>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-hd">
              <div className="chip cyan">📋</div>
              <div>
                <div className="card-title">Manual Decryption Data</div>
                <div className="card-desc">
                  Copy the Encrypted Envelope JSON and Receiver Key JSON for manual decryption demo...
                </div>
              </div>
            </div>

            <div className="status info" style={{ marginBottom: 16 }}>
              Recommended: copy the Encrypted Envelope JSON and Receiver Key JSON
              separately. The private key must remain secret.
            </div>

            <div className="field">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  gap: 10,
                  marginBottom: 8,
                }}
              >
                <label style={{ marginBottom: 0 }}>Encrypted Envelope JSON</label>
                <CopyButton
                  label="Encrypted Envelope JSON"
                  value={result.envelopeJson}
                />
              </div>
              <textarea
                className="inp"
                rows={8}
                readOnly
                value={result.envelopeJson}
              />
            </div>

            <div className="field">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  gap: 10,
                  marginBottom: 8,
                }}
              >
                <label style={{ marginBottom: 0 }}>
                  Receiver RSA Private-Key JSON
                </label>
                <CopyButton
                  label="Receiver Key JSON"
                  value={result.receiverKeyJson}
                />
              </div>
              <textarea
                className="inp"
                rows={6}
                readOnly
                value={result.receiverKeyJson}
              />
            </div>

            <div className="flex-end" style={{ flexWrap: "wrap" }}>
              <button
                type="button"
                className="btn btn-c"
                onClick={() =>
                  copyValue("Full Demo Package", result.fullDemoJson)
                }
              >
                {copied === "Full Demo Package"
                  ? "✓ Full Package Copied"
                  : "📋 Copy Full Demo Package"}
              </button>
            </div>
          </div>
          <div className="card">
            <div className="card-hd">
              <div className="chip purple">📊</div>
              <div>
                <div className="card-title">Performance Metrics</div>
                <div className="card-desc">Computational cost per operation</div>
              </div>
            </div>

            <div className="perf-grid">
              <div className="pbox">
                <div className="pval" style={{ color: "var(--cyan)" }}>
                  {result.perf.rsa}
                </div>
                <div className="punit">ms · RSA keygen</div>
              </div>

              <div className="pbox">
                <div className="pval" style={{ color: "var(--green)" }}>
                  {result.perf.aes}
                </div>
                <div className="punit">ms · AES-GCM enc</div>
              </div>

              <div className="pbox">
                <div className="pval" style={{ color: "var(--amber)" }}>
                  {result.perf.wrap}
                </div>
                <div className="punit">ms · RSA key wrap</div>
              </div>

              <div className="pbox">
                <div className="pval" style={{ color: "var(--purple)" }}>
                  {result.perf.total}
                </div>
                <div className="punit">ms · total</div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}