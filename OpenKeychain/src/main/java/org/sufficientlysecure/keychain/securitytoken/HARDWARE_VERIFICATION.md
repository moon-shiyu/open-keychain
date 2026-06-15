# Hardware Verification Checklist

This document lists verification items for the security token refactoring that **cannot be covered
by unit tests** and must be validated on real hardware.

## Automated Test Coverage

The following components have unit test coverage (via Robolectric + Mockito):

| Component | Test File | Coverage |
|-----------|-----------|----------|
| `PinState` | `PinStateTest.java` | Full — all state transitions, invalidation, reset |
| `ApduCommunicator` | `ApduCommunicatorTest.java` | Full — extended/short/chaining, GET RESPONSE loop, error propagation |
| `ConnectionStatus` | (inline in SecurityTokenConnectionTest) | State validation in communicate() |
| `SecurityTokenConnection` | `SecurityTokenConnectionTest.java` | Connection lifecycle, disconnect, status management |
| `CommandApdu` / `ResponseApdu` | `CommandApduTest.java` | APDU encoding/decoding (unchanged) |
| `CcidTransceiver` | `CcidTransceiverTest.java` | USB CCID framing (unchanged) |
| `PsoDecryptTokenOp` | `PsoDecryptTokenOpTest.java` | RSA decrypt path (unchanged) |
| `ResetAndWipeTokenOp` | `ResetAndWipeTokenOpTest.java` | Reset and wipe flow (unchanged) |
| `SecurityTokenChangeKeyTokenOp` | `SecurityTokenChangeKeyTokenOpTest.java` | RSA key import (unchanged) |

## Hardware-Only Verification Items

### NFC Transport

- [ ] **NFC tap connection**: Tap Yubikey/Nitrokey via NFC → verify `connectToDevice()` completes
  and `ConnectionStatus.CONNECTED` is set
- [ ] **NFC tag removal during operation**: Remove NFC token mid-operation → verify
  `ConnectionStatus.DISCONNECTED` is set and IOException propagates correctly
- [ ] **NFC reconnection**: Re-tap NFC token → verify `getInstanceForTransport()` creates a new
  instance (NFC doesn't allow persistent connections)

### USB Transport

- [ ] **USB CCID connection**: Plug in Yubikey 5 / Nitrokey Pro → verify USB transport connects
  and selects the correct protocol (T=0 or T=1)
- [ ] **USB device unplug during operation**: Unplug USB token mid-operation → verify error
  handling and status transition to DISCONNECTED
- [ ] **USB token whitelist**: Plug in untested USB token with experimental USB disabled → verify
  `UnsupportedUsbTokenException`
- [ ] **T=1 TPDU protocol**: Test with token supporting T=1 TPDU-level exchange → verify I-block,
  R-block, S-block handling
- [ ] **NitroKey 3 timeout quirk**: Test with NitroKey 3 → verify receive retry logic handles
  device-specific timeout behavior

### APDU Communication

- [ ] **Extended APDU**: Test with Yubikey 5 (supports extended) → verify large commands are sent
  as single extended APDUs
- [ ] **Command chaining**: Test with Gnuk or older Yubikey Neo → verify CLA bit 4 chaining works
  correctly for oversized commands
- [ ] **GET RESPONSE chaining**: Test with token returning SW1=0x61 → verify multi-step GET
  RESPONSE loop accumulates data correctly
- [ ] **Chaining intermediate failure**: Simulate a token that rejects intermediate chain commands
  → verify IOException with position info

### PIN Operations

- [ ] **PW1 mode 81 (signature)**: Verify PIN → sign → verify `invalidateSingleUsePw1()` resets
  state when card has `pw1ValidForMultipleSignatures=false`
- [ ] **PW1 mode 81 (multiple signatures)**: Verify PIN → sign twice → second sign should NOT
  require re-verification when card has `pw1ValidForMultipleSignatures=true`
- [ ] **PW1 mode 82 (other)**: Verify PIN → decrypt → verify state remains valid
- [ ] **PW3 (admin)**: Verify admin PIN → key import → verify state management
- [ ] **Bad PIN handling**: Enter wrong PIN → verify `CardException` with correct SW code
- [ ] **PIN retry counter**: Exhaust retries → verify token enters blocked state
- [ ] **KDF-DO**: Test with token configured for KDF (SHA-256 or SHA-512) → verify PIN
  transformation produces correct derived key

### Secure Messaging (SCP11b)

- [ ] **SM establishment**: Test with token supporting SCP11b → verify ECDH key agreement and
  session key derivation
- [ ] **SM transparent encrypt/decrypt**: Verify APDUs are encrypted/decrypted transparently
  during normal operations
- [ ] **SM session timeout**: Leave token idle → verify SM failure is handled gracefully
  (IOException + session cleared)
- [ ] **SM establishment failure**: Test with token reporting SCP11b support but failing
  negotiation → verify connection proceeds in plaintext (non-fatal)

### Token Type Detection

- [ ] **Fidesmo NFC**: Tap Fidesmo token → verify `TokenType.FIDESMO` detected via AID probe
- [ ] **USB VID/PID identification**: Test with Yubikey Neo/4/5, Nitrokey Pro/Start/Storage/3,
  Gnuk, Ledger Nano S, Secalot → verify correct `TokenType`

### Connection Lifecycle

- [ ] **Singleton cache reuse (USB)**: Perform operation → perform second operation → verify
  same `SecurityTokenConnection` instance is reused
- [ ] **Stale cache cleanup**: USB token unplugged → re-plugged → verify
  `getInstanceForTransport()` detects disconnect and creates new instance
- [ ] **`disconnect()` method**: Call disconnect → verify SM cleared, PIN state reset,
  transport released

## Recommended Test Devices

| Device | Transport | Key Algorithms | Notes |
|--------|-----------|---------------|-------|
| Yubikey 5 NFC | NFC + USB | RSA-2048, ECDSA P-256, Ed25519 | Extended APDU, SCP11b SM |
| Yubikey Neo | NFC + USB | RSA-2048 | Command chaining (no extended) |
| Nitrokey Pro 2 | USB | RSA-2048, ECDSA | Standard CCID |
| Nitrokey 3 | USB | ECDSA, Ed25519 | Has timeout quirk |
| Gnuk (FST-01) | USB | RSA-2048, ECDSA | Older firmware may have chaining quirks |
| Fidesmo card | NFC | RSA | Requires AID probe for detection |
