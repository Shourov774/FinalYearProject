import React, { useEffect, useState } from "react";

import Terminal from "../components/terminal";
import Prog from "../components/progs";
import {
  aesDec,
  hmacVerify,
  importAES,
  now,
  rsaDec,
  sha256,
  sleep,
  fmtB,
} from "../cryotoFunction";
import "../CSS/status.css";
import "../CSS/card.css";
import "../CSS/btn.css";

const cleanBase64 = (value = "") =>
  value
    .trim()
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/^data:[^;]+;base64,/, "")
    .replace(/\s+/g, "");

const base64ToBytes = (value, label) => {
  const cleaned = cleanBase64(value);

  if (!cleaned) {
    throw new Error(`${label} is missing`);
  }

  try {
    const binary = window.atob(cleaned);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
  } catch {
    throw new Error(`${label} is not valid Base64`);
  }
};

const parseJson = (value, label) => {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`${label} contains invalid JSON`);
  }
};

const importRsaPrivateKey = async (privateKeyBase64) => {
  const privateKeyBytes = base64ToBytes(
    privateKeyBase64,
    "RSA private key",
  );

  return window.crypto.subtle.importKey(
    "pkcs8",
    privateKeyBytes,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    false,
    ["decrypt"],
  );
};

const safeFileName = (value) => {
  const name = String(value || "decrypted-file.bin").trim();
  return name.replace(/[\\/:*?"<>|]/g, "_") || "decrypted-file.bin";
};

const downloadBlob = (url, fileName) => {
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = safeFileName(fileName);
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
};

const blankManualData = {
  payloadKind: "text",
  fileName: "decrypted-text.txt",
  mimeType: "text/plain;charset=utf-8",
  iv: "",
  ciphertext: "",
  wrappedAesKey: "",
  privateKey: "",
  hmac: "",
  sha256: "",
};

export default function Decrypt() {
  const [inputMode, setInputMode] = useState("json");
  const [envelopeJson, setEnvelopeJson] = useState("");
  const [receiverKeyJson, setReceiverKeyJson] = useState("");
  const [manual, setManual] = useState(blankManualData);
  const [logs, setLogs] = useState([]);
  const [running, setRunning] = useState(false);
  const [prog, setProg] = useState(0);
  const [result, setResult] = useState(null);

  useEffect(() => {
    return () => {
      if (result?.objectUrl) {
        URL.revokeObjectURL(result.objectUrl);
      }
    };
  }, [result]);

  const log = (k, m) => {
    setLogs((items) => [...items, { t: now(), k, m }]);
  };

  const clearResult = () => {
    setLogs([]);
    setProg(0);
    setResult(null);
  };

  const changeMode = (mode) => {
    if (running || mode === inputMode) return;
    setInputMode(mode);
    clearResult();
  };

  const updateManual = (field, value) => {
    setManual((current) => ({ ...current, [field]: value }));
    clearResult();
  };

  const loadJsonFile = async (event, target) => {
    const selectedFile = event.target.files?.[0];
    event.target.value = "";

    if (!selectedFile) return;

    try {
      const text = await selectedFile.text();

      if (target === "envelope") {
        setEnvelopeJson(text);
      } else {
        setReceiverKeyJson(text);
      }

      clearResult();
    } catch (error) {
      clearResult();
      setLogs([{ t: now(), k: "ERR", m: error.message }]);
    }
  };

  const getDecryptionData = () => {
    if (inputMode === "manual") {
      return {
        envelope: {
          schema: "hybrid-crypto-envelope",
          version: 2,
          inputType: manual.payloadKind,
          payload: {
            kind: manual.payloadKind,
            name:
              manual.payloadKind === "text"
                ? manual.fileName || "decrypted-text.txt"
                : manual.fileName || "decrypted-file.bin",
            type:
              manual.mimeType ||
              (manual.payloadKind === "text"
                ? "text/plain;charset=utf-8"
                : "application/octet-stream"),
          },
          iv: manual.iv,
          ciphertext: manual.ciphertext,
          wrappedAesKey: manual.wrappedAesKey,
          hmac: manual.hmac,
          sha256: manual.sha256.trim().toLowerCase(),
        },
        receiverKey: {
          schema: "hybrid-crypto-receiver-key",
          format: "pkcs8",
          privateKey: manual.privateKey,
        },
      };
    }

    if (!envelopeJson.trim()) {
      throw new Error("Paste or upload the encrypted JSON first");
    }

    const firstObject = parseJson(envelopeJson, "Encrypted JSON");

    if (
      firstObject.schema === "hybrid-crypto-full-demo-package" ||
      (firstObject.envelope && firstObject.receiverKey)
    ) {
      return {
        envelope: firstObject.envelope,
        receiverKey: firstObject.receiverKey,
      };
    }

    const envelope = firstObject;

    if (!receiverKeyJson.trim()) {
      throw new Error(
        "This is an Envelope JSON. Paste or upload the Receiver Key JSON too",
      );
    }

    return {
      envelope,
      receiverKey: parseJson(receiverKeyJson, "Receiver Key JSON"),
    };
  };

  const validateData = (envelope, receiverKey) => {
    if (!envelope || typeof envelope !== "object") {
      throw new Error("Encrypted envelope is missing");
    }

    if (!receiverKey || typeof receiverKey !== "object") {
      throw new Error("Receiver private-key data is missing");
    }

    if (!envelope.ciphertext) throw new Error("Ciphertext is missing");
    if (!envelope.iv) throw new Error("AES-GCM IV is missing");
    if (!envelope.wrappedAesKey) {
      throw new Error("RSA-wrapped AES key is missing");
    }
    if (!receiverKey.privateKey) {
      throw new Error("RSA private key is missing");
    }
  };

  const run = async () => {
    setRunning(true);
    setLogs([]);
    setProg(0);
    setResult(null);

    try {
      const startedAt = performance.now();
      const { envelope, receiverKey } = getDecryptionData();
      validateData(envelope, receiverKey);

      const payload = envelope.payload || {
        kind: envelope.inputType || "file",
        name: envelope.file?.name || "decrypted-file.bin",
        type: envelope.file?.type || "application/octet-stream",
        size: envelope.file?.size,
      };

      const payloadKind = payload.kind === "text" ? "text" : "file";
      const fileName = safeFileName(
        payload.name ||
          (payloadKind === "text"
            ? "decrypted-text.txt"
            : "decrypted-file.bin"),
      );
      const mimeType =
        payload.type ||
        (payloadKind === "text"
          ? "text/plain;charset=utf-8"
          : "application/octet-stream");

      log("INFO", "Encrypted envelope loaded successfully");
      log(
        "DATA",
        `Payload: ${payloadKind} | ${fileName} | ${mimeType}`,
      );
      setProg(10);
      await sleep(60);

      const iv = base64ToBytes(envelope.iv, "AES-GCM IV");
      const ciphertext = base64ToBytes(
        envelope.ciphertext,
        "Ciphertext",
      );
      const wrappedAesKey = base64ToBytes(
        envelope.wrappedAesKey,
        "Wrapped AES key",
      );

      if (iv.byteLength !== 12) {
        log(
          "ERR",
          `Warning: AES-GCM normally uses a 12-byte IV; received ${iv.byteLength} bytes`,
        );
      }

      log("INFO", "Importing RSA-OAEP private key...");
      const rsaPrivateKey = await importRsaPrivateKey(receiverKey.privateKey);
      log("OK", "RSA private key imported");
      setProg(22);
      await sleep(60);

      log("INFO", "Unwrapping AES-256 session key with RSA-OAEP...");
      const unwrapStartedAt = performance.now();
      const aesRaw = await rsaDec(rsaPrivateKey, wrappedAesKey);
      const unwrapT = (performance.now() - unwrapStartedAt).toFixed(0);
      log("OK", `AES session key recovered in ${unwrapT}ms`);
      setProg(40);
      await sleep(60);

      const aesKey = await importAES(aesRaw);

      log("INFO", "Decrypting ciphertext with AES-256-GCM...");
      const decryptStartedAt = performance.now();
      const plaintextBuffer = await aesDec(aesKey, iv, ciphertext);
      const decT = (performance.now() - decryptStartedAt).toFixed(0);
      const plaintext = new Uint8Array(plaintextBuffer);
      log(
        "OK",
        `Decryption complete in ${decT}ms | Recovered: ${fmtB(plaintext.byteLength)}`,
      );
      setProg(62);
      await sleep(60);

      let hmacOk = null;
      if (envelope.hmac) {
        log("INFO", "Verifying HMAC-SHA256 integrity tag...");
        const hmacBytes = base64ToBytes(envelope.hmac, "HMAC");
        hmacOk = await hmacVerify(aesRaw, hmacBytes, plaintext);
        log(
          hmacOk ? "OK" : "ERR",
          `HMAC verification: ${hmacOk ? "PASSED ✓" : "FAILED ✗"}`,
        );
      } else {
        log("DATA", "HMAC was not provided; HMAC verification skipped");
      }
      setProg(78);
      await sleep(60);

      log("INFO", "Recomputing SHA-256 fingerprint...");
      const hashStartedAt = performance.now();
      const recomputedHash = await sha256(plaintext);
      const hashT = (performance.now() - hashStartedAt).toFixed(0);
      const expectedHash = String(envelope.sha256 || "")
        .trim()
        .toLowerCase();
      const hashOk = expectedHash
        ? recomputedHash.toLowerCase() === expectedHash
        : null;

      if (hashOk === null) {
        log("DATA", `SHA-256: ${recomputedHash}`);
        log("DATA", "Expected SHA-256 was not provided; comparison skipped");
      } else {
        log(
          hashOk ? "OK" : "ERR",
          `SHA-256 match: ${hashOk ? "VERIFIED ✓" : "MISMATCH ✗"} (${hashT}ms)`,
        );
      }
      setProg(92);
      await sleep(60);

      const integrityFailed = hmacOk === false || hashOk === false;
      const integrityVerified = hmacOk === true && hashOk === true;
      const blob = new Blob([plaintext], { type: mimeType });
      const objectUrl = URL.createObjectURL(blob);
      const isImage = mimeType.toLowerCase().startsWith("image/");
      const isText = payloadKind === "text";
      const recoveredText = isText
        ? new TextDecoder("utf-8").decode(plaintext)
        : "";
      const total = (performance.now() - startedAt).toFixed(0);

      log(
        integrityFailed ? "ERR" : "OK",
        integrityFailed
          ? `Pipeline completed in ${total}ms — tampering or incorrect data detected`
          : `✓ Pipeline completed in ${total}ms`,
      );
      setProg(100);

      setResult({
        payloadKind,
        fileName,
        mimeType,
        size: plaintext.byteLength,
        text: recoveredText,
        isImage,
        objectUrl,
        hash: recomputedHash,
        hmacOk,
        hashOk,
        integrityFailed,
        integrityVerified,
        unwrapT,
        decT,
        hashT,
        total,
      });
    } catch (error) {
      log("ERR", error.message || "Decryption failed");
      setProg(0);
    } finally {
      setRunning(false);
    }
  };

  const resetAll = () => {
    setEnvelopeJson("");
    setReceiverKeyJson("");
    setManual(blankManualData);
    clearResult();
  };

  const hasJsonInput = envelopeJson.trim().length > 0;
  const hasManualInput =
    manual.iv.trim() &&
    manual.ciphertext.trim() &&
    manual.wrappedAesKey.trim() &&
    manual.privateKey.trim();
  const canRun = inputMode === "json" ? hasJsonInput : hasManualInput;

  const modeButtonStyle = (mode) => ({
    flex: 1,
    minHeight: 46,
    borderRadius: 9,
    border:
      inputMode === mode
        ? "1px solid var(--purple)"
        : "1px solid var(--border, rgba(255,255,255,.14))",
    background:
      inputMode === mode
        ? "rgba(167, 139, 250, 0.14)"
        : "rgba(255,255,255,0.03)",
    color: inputMode === mode ? "var(--purple)" : "var(--text, inherit)",
    fontWeight: 700,
    cursor: running ? "not-allowed" : "pointer",
    opacity: running ? 0.7 : 1,
  });

  const integrityLabel = (value) => {
    if (value === true) return "✓ PASS";
    if (value === false) return "✗ FAIL";
    return "— NOT PROVIDED";
  };

  return (
    <div>
      <div className="page-header">
        <div className="page-title">🔓 Decrypt & Verify</div>
        <div className="page-sub">
          RSA-OAEP unwrap → AES-256-GCM decrypt → HMAC verify → SHA-256 check
        </div>
      </div>

      <div className="card">
        <div className="card-hd">
          <div className="chip purple">🔓</div>
          <div>
            <div className="card-title">Decryption Input</div>
            <div className="card-desc">
              Paste JSON packages or enter every cryptographic value manually
            </div>
          </div>
        </div>

        <div className="field">
          <label>Input Method</label>
          <div style={{ display: "flex", gap: 10, width: "100%" }}>
            <button
              type="button"
              style={modeButtonStyle("json")}
              onClick={() => changeMode("json")}
              disabled={running}
            >
              📦 JSON Package
            </button>
            <button
              type="button"
              style={modeButtonStyle("manual")}
              onClick={() => changeMode("manual")}
              disabled={running}
            >
              ⌨️ Manual Fields
            </button>
          </div>
        </div>

        {inputMode === "json" ? (
          <>
            <div className="status info" style={{ marginBottom: 16 }}>
              Paste a Full Demo Package JSON below, or paste the Encrypted
              Envelope JSON and Receiver Key JSON separately.
            </div>

            <div className="field">
              <label>Full Demo Package or Encrypted Envelope JSON</label>
              <textarea
                className="inp"
                rows={10}
                value={envelopeJson}
                disabled={running}
                onChange={(event) => {
                  setEnvelopeJson(event.target.value);
                  clearResult();
                }}
                placeholder='Paste JSON containing "envelope" and "receiverKey", or paste the Encrypted Envelope JSON...'
                style={{ resize: "vertical", minHeight: 190 }}
              />
            </div>

            <div className="field">
              <label>Receiver RSA Private-Key JSON</label>
              <textarea
                className="inp"
                rows={7}
                value={receiverKeyJson}
                disabled={running}
                onChange={(event) => {
                  setReceiverKeyJson(event.target.value);
                  clearResult();
                }}
                placeholder="Not needed when the first box contains a Full Demo Package. Otherwise paste Receiver Key JSON here..."
                style={{ resize: "vertical", minHeight: 135 }}
              />
            </div>
          </>
        ) : (
          <>
            <div className="status info" style={{ marginBottom: 16 }}>
              Copy the Base64 values from the Encrypt page. IV, ciphertext,
              wrapped AES key and RSA private key are required. HMAC and SHA-256
              are used for integrity verification.
            </div>

            <div className="row2">
              <div className="field">
                <label>Recovered Content Type</label>
                <select
                  className="inp"
                  value={manual.payloadKind}
                  disabled={running}
                  onChange={(event) =>
                    updateManual("payloadKind", event.target.value)
                  }
                >
                  <option value="text">Text</option>
                  <option value="file">File / Image</option>
                </select>
              </div>

              <div className="field">
                <label>Original File Name</label>
                <input
                  className="inp"
                  value={manual.fileName}
                  disabled={running}
                  onChange={(event) =>
                    updateManual("fileName", event.target.value)
                  }
                  placeholder="example.png or decrypted-text.txt"
                />
              </div>
            </div>

            <div className="field">
              <label>MIME Type</label>
              <input
                className="inp"
                value={manual.mimeType}
                disabled={running}
                onChange={(event) =>
                  updateManual("mimeType", event.target.value)
                }
                placeholder="image/png, application/pdf or text/plain;charset=utf-8"
              />
            </div>

            <div className="field">
              <label>AES-GCM IV — Base64</label>
              <textarea
                className="inp"
                rows={3}
                value={manual.iv}
                disabled={running}
                onChange={(event) => updateManual("iv", event.target.value)}
                placeholder="Paste envelope.iv"
              />
            </div>

            <div className="field">
              <label>Ciphertext — Base64</label>
              <textarea
                className="inp"
                rows={8}
                value={manual.ciphertext}
                disabled={running}
                onChange={(event) =>
                  updateManual("ciphertext", event.target.value)
                }
                placeholder="Paste envelope.ciphertext"
                style={{ resize: "vertical", minHeight: 150 }}
              />
            </div>

            <div className="field">
              <label>RSA-Wrapped AES Key — Base64</label>
              <textarea
                className="inp"
                rows={4}
                value={manual.wrappedAesKey}
                disabled={running}
                onChange={(event) =>
                  updateManual("wrappedAesKey", event.target.value)
                }
                placeholder="Paste envelope.wrappedAesKey"
              />
            </div>

            <div className="field">
              <label>RSA Private Key PKCS8 — Base64</label>
              <textarea
                className="inp"
                rows={7}
                value={manual.privateKey}
                disabled={running}
                onChange={(event) =>
                  updateManual("privateKey", event.target.value)
                }
                placeholder="Paste receiverKey.privateKey"
                style={{ resize: "vertical", minHeight: 135 }}
              />
            </div>

            <div className="field">
              <label>HMAC-SHA256 — Base64</label>
              <textarea
                className="inp"
                rows={3}
                value={manual.hmac}
                disabled={running}
                onChange={(event) => updateManual("hmac", event.target.value)}
                placeholder="Paste envelope.hmac (recommended)"
              />
            </div>

            <div className="field">
              <label>Original SHA-256 — Hex</label>
              <textarea
                className="inp"
                rows={3}
                value={manual.sha256}
                disabled={running}
                onChange={(event) =>
                  updateManual("sha256", event.target.value)
                }
                placeholder="Paste envelope.sha256 (recommended)"
              />
            </div>
          </>
        )}

        <div className="flex-end">
          <button
            type="button"
            className="btn btn-ghost"
            onClick={resetAll}
            disabled={running}
          >
            🧹 Clear
          </button>
          <button
            type="button"
            className="btn btn-c"
            onClick={run}
            disabled={!canRun || running}
          >
            {running ? "⏳ Decrypting..." : "🔓 Decrypt & Verify"}
          </button>
        </div>
      </div>

      {logs.length > 0 && (
        <div className="card">
          <div className="card-hd">
            <div className="chip amber">⚙️</div>
            <div>
              <div className="card-title">Decryption Log</div>
              <div className="card-desc">
                Step-by-step RSA, AES and integrity verification
              </div>
            </div>
          </div>

          {prog > 0 && (
            <Prog
              val={prog}
              color="g"
              label="RSA Unwrap → AES Decrypt → HMAC → SHA-256"
            />
          )}
          <Terminal logs={logs} running={running} />
        </div>
      )}

      {result && (
        <div className="card">
          <div className="card-hd">
            <div className={result.integrityFailed ? "chip red" : "chip green"}>
              {result.integrityFailed ? "⚠️" : "✅"}
            </div>
            <div>
              <div className="card-title">Recovered Content</div>
              <div className="card-desc">
                Original {result.payloadKind} reconstructed from encrypted data
              </div>
            </div>
          </div>

          <div
            className={`status ${result.integrityFailed ? "err" : result.integrityVerified ? "ok" : "info"}`}
            style={{ marginBottom: 14 }}
          >
            {result.integrityFailed
              ? "✗ INTEGRITY FAILURE — wrong data, wrong key or tampering detected"
              : result.integrityVerified
                ? "✓ INTEGRITY VERIFIED — HMAC and SHA-256 both passed"
                : "✓ DECRYPTION COMPLETE — one or more integrity values were not provided"}
          </div>

          {result.payloadKind === "text" && (
            <div className="field">
              <label>Recovered Plaintext</label>
              <textarea
                className="inp"
                rows={11}
                readOnly
                value={result.text}
                style={{ resize: "vertical", minHeight: 210 }}
              />
            </div>
          )}

          {result.isImage && (
            <div className="field">
              <label>Recovered Image Preview</label>
              <div
                className="obox"
                style={{ textAlign: "center", overflow: "hidden" }}
              >
                <img
                  src={result.objectUrl}
                  alt={result.fileName}
                  style={{
                    display: "block",
                    maxWidth: "100%",
                    maxHeight: 520,
                    margin: "0 auto",
                    objectFit: "contain",
                    borderRadius: 8,
                  }}
                />
              </div>
            </div>
          )}

          <div className="grid2">
            <div className="obox">
              <div className="olbl">Recovered Item</div>
              <div className="oval cyan">
                {result.fileName}
                <br />
                <span style={{ color: "var(--muted)" }}>
                  {result.mimeType} · {fmtB(result.size)}
                </span>
              </div>
            </div>

            <div className="obox">
              <div className="olbl">Verification Summary</div>
              <div
                style={{
                  fontFamily: "var(--mono)",
                  fontSize: 11,
                  lineHeight: 2,
                }}
              >
                <div>
                  <span style={{ color: "var(--muted)" }}>HMAC-SHA256: </span>
                  <span
                    style={{
                      color:
                        result.hmacOk === false
                          ? "var(--red)"
                          : result.hmacOk === true
                            ? "var(--green)"
                            : "var(--muted)",
                    }}
                  >
                    {integrityLabel(result.hmacOk)}
                  </span>
                </div>
                <div>
                  <span style={{ color: "var(--muted)" }}>SHA-256 hash: </span>
                  <span
                    style={{
                      color:
                        result.hashOk === false
                          ? "var(--red)"
                          : result.hashOk === true
                            ? "var(--green)"
                            : "var(--muted)",
                    }}
                  >
                    {integrityLabel(result.hashOk)}
                  </span>
                </div>
                <div>
                  <span style={{ color: "var(--muted)" }}>RSA unwrap: </span>
                  <span style={{ color: "var(--green)" }}>
                    ✓ {result.unwrapT}ms
                  </span>
                </div>
                <div>
                  <span style={{ color: "var(--muted)" }}>AES decrypt: </span>
                  <span style={{ color: "var(--green)" }}>
                    ✓ {result.decT}ms
                  </span>
                </div>
                <div>
                  <span style={{ color: "var(--muted)" }}>Total time: </span>
                  <span style={{ color: "var(--cyan)" }}>
                    {result.total}ms
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="field" style={{ marginTop: 16 }}>
            <label>SHA-256 Recomputed</label>
            <div className="obox">
              <div className="oval purple">
                {result.hash.slice(0, 32)}
                <br />
                {result.hash.slice(32)}
              </div>
            </div>
          </div>

          <div className="flex-end">
            <button
              type="button"
              className="btn btn-c"
              onClick={() => downloadBlob(result.objectUrl, result.fileName)}
            >
              ⬇️ Download Original {result.payloadKind === "text" ? "Text" : "File"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}