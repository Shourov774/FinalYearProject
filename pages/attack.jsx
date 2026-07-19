import { useRef, useState } from "react";

import {
  genAES,
  genRSA,
  aesEnc,
  aesDec,
  rsaEnc,
  rsaDec,
  sha256,
  toHex,
  fmtB,
  sleep,
  now,
} from "../cryotoFunction";

import Terminal from "../components/terminal";
import EcbEncSimulate from "../ECB_Simulation";

import "../CSS/status.css";
import "../CSS/attack.css";
import "../CSS/card.css";
import "../CSS/btn.css";

/* -------------------------------------------------------
   Helper functions
------------------------------------------------------- */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Converts ArrayBuffer or Uint8Array into Uint8Array.
 */
const toBytes = (value) => {
  if (value instanceof Uint8Array) {
    return value;
  }

  return new Uint8Array(value);
};

/**
 * Compares two byte arrays.
 */
const bytesEqual = (first, second) => {
  const firstBytes = toBytes(first);
  const secondBytes = toBytes(second);

  if (firstBytes.length !== secondBytes.length) {
    return false;
  }

  return firstBytes.every(
    (value, index) => value === secondBytes[index]
  );
};

/**
 * Creates a cryptographically random request ID.
 */
const createRequestId = () => {
  const randomBytes = window.crypto.getRandomValues(
    new Uint8Array(16)
  );

  return toHex(randomBytes);
};

/**
 * Returns a readable error message.
 */
const getErrorMessage = (error) => {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
};

/**
 * Generates a SHA-256 fingerprint of an RSA public key.
 *
 * Note:
 * genRSA() must generate extractable public keys so that
 * the SPKI representation can be exported.
 */
const getPublicKeyFingerprint = async (publicKey) => {
  const exportedKey = await window.crypto.subtle.exportKey(
    "spki",
    publicKey
  );

  return sha256(new Uint8Array(exportedKey));
};

/* -------------------------------------------------------
   Attack Simulation Component
------------------------------------------------------- */

export default function Attack() {
  const [open, setOpen] = useState(null);
  const [logs, setLogs] = useState({});
  const [running, setRunning] = useState(null);
  const [results, setResults] = useState({});

  /*
   * Prevents rapid double-clicking from starting two
   * simulations before React finishes updating the state.
   */
  const runLock = useRef(false);

  /**
   * Adds a new terminal log entry.
   */
  const log = (id, kind, message) => {
    setLogs((previousLogs) => ({
      ...previousLogs,
      [id]: [
        ...(previousLogs[id] || []),
        {
          t: now(),
          k: kind,
          m: message,
        },
      ],
    }));
  };

  /**
   * Updates the result of one simulation.
   */
  const setResult = (id, result) => {
    setResults((previousResults) => ({
      ...previousResults,
      [id]: result,
    }));
  };

  /**
   * Starts a simulation and clears its previous output.
   */
  const beginAttack = (id) => {
    if (runLock.current) {
      return false;
    }

    runLock.current = true;
    setRunning(id);

    setLogs((previousLogs) => ({
      ...previousLogs,
      [id]: [],
    }));

    setResult(id, null);

    return true;
  };

  /**
   * Releases the simulation lock.
   */
  const finishAttack = () => {
    runLock.current = false;
    setRunning(null);
  };

  /**
   * Handles unexpected simulation errors.
   */
  const handleSimulationError = (id, error) => {
    const message = getErrorMessage(error);

    log(id, "ERR", `[SYSTEM] Simulation failed: ${message}`);

    setResult(id, {
      success: false,
      badge: "FAILED",
      detail: `The simulation could not be completed: ${message}`,
    });
  };

  /* =====================================================
     ATTACK 1: MAN-IN-THE-MIDDLE
  ===================================================== */

  const runMITM = async () => {
    const id = "mitm";

    if (!beginAttack(id)) {
      return;
    }

    try {
      log(
        id,
        "INFO",
        "[SYSTEM] Generating legitimate and attacker RSA-2048 key pairs..."
      );

      const legitimateKeyPair = await genRSA(2048);
      const rogueKeyPair = await genRSA(2048);

      await sleep(300);

      const legitimateFingerprint =
        await getPublicKeyFingerprint(
          legitimateKeyPair.publicKey
        );

      const rogueFingerprint =
        await getPublicKeyFingerprint(
          rogueKeyPair.publicKey
        );

      log(
        id,
        "DATA",
        `[SERVER] Pinned key fingerprint: ${legitimateFingerprint.slice(
          0,
          32
        )}...`
      );

      await sleep(350);

      log(
        id,
        "WARN",
        "[ATTACKER] Intercepting the RSA public-key exchange..."
      );

      await sleep(400);

      log(
        id,
        "ERR",
        "[ATTACKER] Replacing the legitimate RSA public key with a rogue key..."
      );

      await sleep(400);

      /*
       * This phase demonstrates what would happen if the
       * client did not authenticate the received public key.
       */
      const sessionKey = window.crypto.getRandomValues(
        new Uint8Array(32)
      );

      log(
        id,
        "WARN",
        "[CLIENT] No key authentication enabled. Encrypting session key with received public key..."
      );

      const wrappedByRogueKey = await rsaEnc(
        rogueKeyPair.publicKey,
        sessionKey
      );

      log(
        id,
        "DATA",
        `[NETWORK] Wrapped session-key size: ${fmtB(
          wrappedByRogueKey.byteLength
        )}`
      );

      await sleep(350);

      const recoveredSessionKey = await rsaDec(
        rogueKeyPair.privateKey,
        wrappedByRogueKey
      );

      const attackerRecoveredKey = bytesEqual(
        sessionKey,
        recoveredSessionKey
      );

      if (!attackerRecoveredKey) {
        throw new Error(
          "Attacker could not recover the session key."
        );
      }

      log(
        id,
        "ERR",
        "[ATTACKER] Rogue private key successfully decrypted the session key!"
      );

      log(
        id,
        "WARN",
        "[DEMO] Without public-key authentication, the MITM attack succeeds."
      );

      await sleep(500);

      /*
       * Mitigation phase:
       * The client compares the received public-key fingerprint
       * with its trusted pinned fingerprint.
       */
      log(
        id,
        "INFO",
        "[MITIGATION] Enabling SHA-256 public-key fingerprint pinning..."
      );

      await sleep(350);

      log(
        id,
        "DATA",
        `[CLIENT] Received key fingerprint: ${rogueFingerprint.slice(
          0,
          32
        )}...`
      );

      const fingerprintMismatch =
        legitimateFingerprint !== rogueFingerprint;

      if (fingerprintMismatch) {
        log(
          id,
          "WARN",
          "[MITIGATION] Received fingerprint does not match the pinned server fingerprint."
        );

        await sleep(300);

        log(
          id,
          "OK",
          "[SYSTEM] MITM attack BLOCKED — rogue public key rejected before session-key transmission."
        );
      } else {
        throw new Error(
          "Rogue key unexpectedly matched the pinned fingerprint."
        );
      }

      setResult(id, {
        success:
          attackerRecoveredKey && fingerprintMismatch,
        badge: "BLOCKED",
        detail:
          "The demonstration first showed that an unauthenticated RSA key exchange can be intercepted. SHA-256 public-key fingerprint pinning then detected and rejected the rogue RSA key.",
      });
    } catch (error) {
      handleSimulationError(id, error);
    } finally {
      finishAttack();
    }
  };

  /* =====================================================
     ATTACK 2: REPLAY ATTACK
  ===================================================== */

  const runReplay = async () => {
    const id = "replay";

    if (!beginAttack(id)) {
      return;
    }

    try {
      const aesKey = await genAES();
      const requestId = createRequestId();
      const timestamp = Date.now();

      /*
       * The request ID and timestamp are included inside the
       * encrypted and authenticated AES-GCM payload.
       */
      const requestPayload = {
        requestId,
        timestamp,
        action: "Transfer $5000 to account 99887766",
      };

      const encodedPayload = encoder.encode(
        JSON.stringify(requestPayload)
      );

      log(
        id,
        "INFO",
        "[CLIENT] Creating an authenticated transfer request..."
      );

      log(
        id,
        "DATA",
        `[CLIENT] Request ID: ${requestId}`
      );

      log(
        id,
        "DATA",
        `[CLIENT] Timestamp: ${timestamp}`
      );

      const encryptedPacket = await aesEnc(
        aesKey,
        encodedPayload
      );

      const packet = {
        iv: encryptedPacket.iv,
        ct: encryptedPacket.ct,
      };

      await sleep(350);

      log(
        id,
        "WARN",
        `[ATTACKER] Captured packet: IV=${toHex(
          packet.iv
        ).slice(0, 24)}...`
      );

      log(
        id,
        "WARN",
        `[ATTACKER] Ciphertext size: ${fmtB(
          packet.ct.byteLength
        )}`
      );

      /*
       * Simulated server-side replay registry.
       * In a real system, this must be stored securely on
       * the server, database, or session store.
       */
      const seenRequestIds = new Set();
      const maximumPacketAge = 30_000;

      const receivePacket = async (receivedPacket) => {
        let decryptedData;

        try {
          decryptedData = await aesDec(
            aesKey,
            receivedPacket.iv,
            receivedPacket.ct
          );
        } catch {
          return {
            accepted: false,
            reason:
              "AES-GCM authentication failed.",
          };
        }

        let parsedPayload;

        try {
          parsedPayload = JSON.parse(
            decoder.decode(decryptedData)
          );
        } catch {
          return {
            accepted: false,
            reason: "Invalid decrypted packet format.",
          };
        }

        const packetAge =
          Date.now() - parsedPayload.timestamp;

        if (
          packetAge < -5_000 ||
          packetAge > maximumPacketAge
        ) {
          return {
            accepted: false,
            reason:
              "Packet timestamp is outside the allowed time window.",
            payload: parsedPayload,
          };
        }

        if (
          seenRequestIds.has(parsedPayload.requestId)
        ) {
          return {
            accepted: false,
            reason:
              "Duplicate authenticated request ID detected.",
            payload: parsedPayload,
          };
        }

        seenRequestIds.add(parsedPayload.requestId);

        return {
          accepted: true,
          reason: "Fresh authenticated request accepted.",
          payload: parsedPayload,
        };
      };

      log(
        id,
        "INFO",
        "[SERVER] Receiving original encrypted packet..."
      );

      const firstResponse = await receivePacket(packet);

      if (!firstResponse.accepted) {
        throw new Error(
          `Original packet rejected: ${firstResponse.reason}`
        );
      }

      log(
        id,
        "OK",
        `[SERVER] Original request accepted — ID ${firstResponse.payload.requestId}`
      );

      await sleep(450);

      log(
        id,
        "ERR",
        "[ATTACKER] Replaying the exact same IV and ciphertext..."
      );

      await sleep(400);

      const replayResponse = await receivePacket(packet);

      if (replayResponse.accepted) {
        log(
          id,
          "ERR",
          "[SERVER] Replayed packet was incorrectly accepted!"
        );

        setResult(id, {
          success: false,
          badge: "FAILED",
          detail:
            "The replay protection failed because the duplicate packet was accepted.",
        });

        return;
      }

      log(
        id,
        "WARN",
        `[MITIGATION] ${replayResponse.reason}`
      );

      await sleep(300);

      log(
        id,
        "OK",
        "[SYSTEM] Replay attack BLOCKED — duplicate authenticated request rejected."
      );

      setResult(id, {
        success: true,
        badge: "BLOCKED",
        detail:
          "The first authenticated request was accepted. Replaying the same ciphertext produced the same request ID, allowing the server-side replay registry to reject the duplicate request.",
      });
    } catch (error) {
      handleSimulationError(id, error);
    } finally {
      finishAttack();
    }
  };

  /* =====================================================
     ATTACK 3: DATA TAMPERING
  ===================================================== */

  const runTamper = async () => {
    const id = "tamper";

    if (!beginAttack(id)) {
      return;
    }

    try {
      const message = "Pay $100 to Shourov";
      const plaintext = encoder.encode(message);
      const aesKey = await genAES();

      log(
        id,
        "INFO",
        `[CLIENT] Original message: "${message}"`
      );

      const originalHash = await sha256(plaintext);

      log(
        id,
        "DATA",
        `[CHECKSUM] SHA-256 fingerprint: ${originalHash.slice(
          0,
          32
        )}...`
      );

      log(
        id,
        "INFO",
        "[CLIENT] Encrypting message with AES-GCM..."
      );

      const encrypted = await aesEnc(
        aesKey,
        plaintext
      );

      log(
        id,
        "DATA",
        `[NETWORK] IV: ${toHex(encrypted.iv)}`
      );

      log(
        id,
        "DATA",
        `[NETWORK] Ciphertext size: ${fmtB(
          encrypted.ct.byteLength
        )}`
      );

      await sleep(400);

      const tamperedCiphertext = new Uint8Array(
        encrypted.ct
      );

      const tamperIndexes = [2, 3, 4].filter(
        (index) => index < tamperedCiphertext.length
      );

      const masks = [0xff, 0xaa, 0x55];

      tamperIndexes.forEach((index, position) => {
        tamperedCiphertext[index] ^=
          masks[position];
      });

      log(
        id,
        "WARN",
        `[ATTACKER] Modified ciphertext bytes at positions: ${tamperIndexes.join(
          ", "
        )}`
      );

      await sleep(350);

      log(
        id,
        "ERR",
        "[ATTACKER] Sending modified ciphertext to the receiver..."
      );

      await sleep(400);

      let tamperedPacketAccepted = false;

      try {
        await aesDec(
          aesKey,
          encrypted.iv,
          tamperedCiphertext
        );

        tamperedPacketAccepted = true;
      } catch {
        tamperedPacketAccepted = false;
      }

      if (tamperedPacketAccepted) {
        log(
          id,
          "ERR",
          "[AES-GCM] Modified ciphertext was unexpectedly accepted."
        );

        setResult(id, {
          success: false,
          badge: "FAILED",
          detail:
            "The modified ciphertext was unexpectedly decrypted. Check the AES-GCM implementation.",
        });

        return;
      }

      log(
        id,
        "OK",
        "[AES-GCM] Authentication tag verification FAILED as expected."
      );

      await sleep(300);

      log(
        id,
        "OK",
        "[MITIGATION] Decryption aborted before modified plaintext could be used."
      );

      await sleep(250);

      log(
        id,
        "OK",
        "[SYSTEM] Tampering attack BLOCKED — AES-GCM detected the ciphertext modification."
      );

      setResult(id, {
        success: true,
        badge: "BLOCKED",
        detail:
          "The attacker changed several ciphertext bytes. AES-GCM authentication detected the modification and refused to return any plaintext.",
      });
    } catch (error) {
      handleSimulationError(id, error);
    } finally {
      finishAttack();
    }
  };

  /* =====================================================
     ATTACK 4: ECB PATTERN LEAKAGE
  ===================================================== */

  const runECB = async () => {
    const id = "ecb";

    if (!beginAttack(id)) {
      return;
    }

    try {
      const structuredMessage =
        "AAAAAAAAAAAAAAAA" +
        "BBBBBBBBBBBBBBBB" +
        "AAAAAAAAAAAAAAAA" +
        "CCCCCCCCCCCCCCCC" +
        "AAAAAAAAAAAAAAAA";

      const plaintext = encoder.encode(
        structuredMessage
      );

      log(
        id,
        "INFO",
        "[ECB] Encrypting five structured 16-byte blocks..."
      );

      log(
        id,
        "DATA",
        "[PLAINTEXT] Blocks 0, 2 and 4 contain identical data."
      );

      const simulatedECBResult = await EcbEncSimulate(
        plaintext
      );

      const ecbBytes = toBytes(simulatedECBResult);

      if (ecbBytes.length < 80) {
        throw new Error(
          "ECB simulation did not return five complete 16-byte blocks."
        );
      }

      const ecbBlocks = Array.from(
        { length: 5 },
        (_, index) => {
          const start = index * 16;
          const end = start + 16;

          return toHex(
            ecbBytes.slice(start, end)
          );
        }
      );

      ecbBlocks.forEach((block, index) => {
        const repeatedBlock =
          index === 2 || index === 4;

        log(
          id,
          repeatedBlock ? "ERR" : "WARN",
          `[ECB] Block ${index}: ${block}${
            index === 2
              ? " ← SAME AS BLOCK 0"
              : index === 4
                ? " ← SAME AS BLOCKS 0 AND 2"
                : ""
          }`
        );
      });

      const repeatedECBPattern =
        ecbBlocks[0] === ecbBlocks[2] &&
        ecbBlocks[0] === ecbBlocks[4];

      if (!repeatedECBPattern) {
        throw new Error(
          "ECB simulation did not preserve identical block patterns."
        );
      }

      await sleep(450);

      log(
        id,
        "INFO",
        "[GCM] Encrypting the same complete message twice with AES-GCM..."
      );

      const aesKey = await genAES();

      const firstGCMEncryption = await aesEnc(
        aesKey,
        plaintext
      );

      const secondGCMEncryption = await aesEnc(
        aesKey,
        plaintext
      );

      const firstCiphertext = toBytes(
        firstGCMEncryption.ct
      );

      const secondCiphertext = toBytes(
        secondGCMEncryption.ct
      );

      const firstIV = toHex(
        firstGCMEncryption.iv
      );

      const secondIV = toHex(
        secondGCMEncryption.iv
      );

      const differentIVs = firstIV !== secondIV;

      const differentCiphertexts =
        !bytesEqual(
          firstCiphertext,
          secondCiphertext
        );

      log(
        id,
        "DATA",
        `[GCM] Encryption 1 IV: ${firstIV}`
      );

      log(
        id,
        "DATA",
        `[GCM] Encryption 2 IV: ${secondIV}`
      );

      log(
        id,
        "DATA",
        `[GCM] Output 1: ${toHex(
          firstCiphertext.slice(0, 16)
        )}...`
      );

      log(
        id,
        "DATA",
        `[GCM] Output 2: ${toHex(
          secondCiphertext.slice(0, 16)
        )}...`
      );

      if (!differentIVs || !differentCiphertexts) {
        throw new Error(
          "AES-GCM did not produce unique encryption output."
        );
      }

      await sleep(350);

      log(
        id,
        "OK",
        "[GCM] Unique IVs produced different ciphertext for the same plaintext."
      );

      log(
        id,
        "OK",
        "[SYSTEM] ECB pattern leakage Prevented — AES-GCM avoids deterministic block patterns."
      );

      setResult(id, {
        success: true,
        badge: "PREVENTED",
        detail:
          "ECB revealed that identical plaintext blocks produced identical ciphertext blocks. AES-GCM used a unique IV for each encryption and produced different authenticated ciphertext.",
        ecbBlocks,
      });
    } catch (error) {
      handleSimulationError(id, error);
    } finally {
      finishAttack();
    }
  };

  /* -------------------------------------------------------
     Attack information
  ------------------------------------------------------- */

  const attacks = [
    {
      id: "mitm",
      label: "MITM",
      title: "Man-in-the-Middle Attack",
      desc: "Rogue RSA public-key injection",
      color: "red",
      run: runMITM,
      explain:
        "An attacker intercepts an unauthenticated RSA key exchange and replaces the legitimate public key with a rogue key.\n\nMitigation: authenticate the public key using certificate validation, digital signatures, or SHA-256 public-key fingerprint pinning.",
    },
    {
      id: "replay",
      label: "REPLAY",
      title: "Replay Attack",
      desc: "Captured encrypted-packet retransmission",
      color: "red",
      run: runReplay,
      explain:
        "An attacker captures a valid encrypted request and sends the exact same packet again. Encryption alone does not prevent replay attacks.\n\nMitigation: include an authenticated unique request ID and timestamp, then keep a server-side registry of previously processed request IDs.",
    },
    {
      id: "tamper",
      label: "TAMPER",
      title: "Data Tampering Attack",
      desc: "Ciphertext bit modification",
      color: "amber",
      run: runTamper,
      explain:
        "An attacker changes one or more ciphertext bytes while the encrypted packet is travelling through the network.\n\nMitigation: AES-GCM provides authenticated encryption. Any change to the ciphertext or authentication tag causes decryption to fail.",
    },
    {
      id: "ecb",
      label: "ECB LEAK",
      title: "ECB Pattern Leakage Demo",
      desc: "Identical plaintext-block pattern exposure",
      color: "amber",
      run: runECB,
      explain:
        "ECB encrypts every 16-byte block independently with the same key. Identical plaintext blocks therefore produce identical ciphertext blocks.\n\nMitigation: use a modern authenticated encryption mode such as AES-GCM with a unique IV for every encryption operation.",
    },
  ];

  /* -------------------------------------------------------
     User interface
  ------------------------------------------------------- */

  return (
    <div>
      <div className="page-header">
        <div className="page-title">
          ⚠️ Attack Simulations
        </div>

        <div className="page-sub">
          Controlled demonstrations of MITM, Replay,
          Tampering and ECB Pattern Leakage
        </div>
      </div>

      <div
        className="status warn"
        style={{ marginBottom: 16 }}
      >
        ⚠️ Browser cryptographic primitives are real.
        Network, attacker, server and ECB workflows are
        controlled academic simulations.
      </div>

      {attacks.map((attack) => {
        const attackResult = results[attack.id];
        const isOpen = open === attack.id;
        const isRunning = running === attack.id;

        return (
          <div
            key={attack.id}
            className="atk-card"
          >
            <button
              type="button"
              className="atk-hd"
              aria-expanded={isOpen}
              aria-controls={`attack-body-${attack.id}`}
              onClick={() =>
                setOpen(
                  isOpen ? null : attack.id
                )
              }
              style={{
                width: "100%",
                border: 0,
                background: "transparent",
                color: "inherit",
                textAlign: "left",
                cursor: "pointer",
              }}
            >
              <div className="atk-hd-left">
                <span
                  className={`atk-badge ${attack.color}`}
                >
                  {attack.label}
                </span>

                <div>
                  <div
                    style={{
                      fontWeight: 700,
                      fontSize: 14,
                    }}
                  >
                    {attack.title}
                  </div>

                  <div
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: 11,
                      color: "var(--muted)",
                      marginTop: 2,
                    }}
                  >
                    {attack.desc}
                  </div>
                </div>
              </div>

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                }}
              >
                {attackResult && (
                  <span
                    style={{
                      color: attackResult.success
                        ? "var(--green)"
                        : "var(--red)",
                      fontSize: 12,
                      fontFamily: "var(--mono)",
                    }}
                  >
                    {attackResult.success
                      ? `✓ ${attackResult.badge}`
                      : "✕ FAILED"}
                  </span>
                )}

                <span
                  style={{
                    color: "var(--muted)",
                    fontSize: 12,
                  }}
                >
                  {isOpen ? "▲" : "▼"}
                </span>
              </div>
            </button>

            {isOpen && (
              <div
                id={`attack-body-${attack.id}`}
                className="atk-body"
              >
                <div
                  style={{
                    fontSize: 13,
                    color: "#8899bb",
                    lineHeight: 1.7,
                    marginBottom: 14,
                    whiteSpace: "pre-line",
                  }}
                >
                  {attack.explain}
                </div>

                <div
                  className="flex-end"
                  style={{
                    marginTop: 0,
                    marginBottom: 14,
                  }}
                >
                  <button
                    type="button"
                    className="btn btn-r btn-sm"
                    onClick={attack.run}
                    disabled={running !== null}
                  >
                    {isRunning
                      ? "⏳ Simulating..."
                      : running !== null
                        ? "Another simulation is running"
                        : "▶ Run Simulation"}
                  </button>
                </div>

                {(logs[attack.id] || []).length >
                  0 && (
                  <Terminal
                    logs={logs[attack.id] || []}
                    running={isRunning}
                  />
                )}

                {attackResult && (
                  <div
                    className={
                      attackResult.success
                        ? "status ok mt12"
                        : "status warn mt12"
                    }
                    aria-live="polite"
                  >
                    {attackResult.success
                      ? `🛡️ ${attackResult.badge} — `
                      : "⚠️ Simulation error — "}

                    {attackResult.detail}
                  </div>
                )}

                {attackResult?.ecbBlocks && (
                  <div className="mt12">
                    <div
                      style={{
                        marginBottom: 8,
                        fontWeight: 600,
                      }}
                    >
                      ECB Block Analysis
                    </div>

                    {attackResult.ecbBlocks.map(
                      (block, index) => {
                        const isRepeated =
                          index === 0 ||
                          index === 2 ||
                          index === 4;

                        return (
                          <div
                            key={`${block}-${index}`}
                            style={{
                              display: "flex",
                              gap: 10,
                              marginBottom: 4,
                              fontFamily:
                                "var(--mono)",
                              fontSize: 11,
                              alignItems: "center",
                              flexWrap: "wrap",
                            }}
                          >
                            <span
                              style={{
                                color:
                                  "var(--muted)",
                                width: 60,
                              }}
                            >
                              Block {index}:
                            </span>

                            <span
                              style={{
                                color: isRepeated
                                  ? "var(--red)"
                                  : "var(--txt)",
                                overflowWrap:
                                  "anywhere",
                              }}
                            >
                              {block}
                            </span>

                            {(index === 2 ||
                              index === 4) && (
                              <span
                                style={{
                                  color:
                                    "var(--red)",
                                }}
                              >
                                ← SAME!
                              </span>
                            )}
                          </div>
                        );
                      }
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}