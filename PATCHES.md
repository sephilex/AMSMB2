# Local patches / source provenance

- AMSMB2 **4.0.3**: [`1726aaaf7adf63d7d1d2a0c5d1b0e635028215c0`](https://github.com/amosavian/AMSMB2/tree/1726aaaf7adf63d7d1d2a0c5d1b0e635028215c0).
- libsmb2: [`aff9fa6ba9f41cfd3c15d184554601ec3f6d8d03`](https://github.com/sahlberg/libsmb2/tree/aff9fa6ba9f41cfd3c15d184554601ec3f6d8d03), matching the upstream gitlink. Both trees were copied from commit archives, as ordinary files.
- Both upstream manifests remain byte-for-byte unchanged; product `AMSMB2` remains `.dynamic`. Swift 6 uses `Package@swift-6.0.swift`.
- Omitted only AMSMB2 `.gitmodules` (flattened dependency) and libsmb2 `.gitignore` (its patterns hide source/distribution inputs such as `*.in` from the enclosing repository). No source, examples, tests, CI or license files were pruned. Build caches are excluded from delivery.
- Original license notices, `LICENSE`, `Dependencies/libsmb2/COPYING` and `LICENCE-LGPL-2.1.txt` are retained. Modified libsmb2 files are distributed here in source form with the patch below. No upstream submission or remote publication was performed; H16b/release must publish the exact modified source and retain the license notices/source link.

## Guest / anonymous signing (2026-10-14)

SMB 3.1.1 forced TREE_CONNECT signing incorrectly uses a locally derived NTLM key even when the server accepted a guest session and has no corresponding usable signing key. Identify sessions from successful SESSION_SETUP `IS_GUEST` / `IS_NULL` flags, never from the supplied username or an arbitrary authentication/key failure.

Changed files under `Dependencies/libsmb2/`:

- `include/libsmb2-private.h`: retain the server session flags in private context state; no public C/Swift API added.
- `lib/libsmb2.c`: save flags on every successful setup; skip key extraction/derivation and setup signature verification only for guest/null; clear flags on error-close and normal disconnect.
- `lib/pdu.c`: exclude guest/null from all outgoing signing, including mandatory SMB 3.1.1 TREE_CONNECT signing.
- `lib/socket.c`: exclude guest/null from subsequent incoming signature verification, avoiding failure with an unusable key.

Keep `smb2->sign` intact, so a later authenticated session retains its signing configuration. Authenticated sessions run the original key derivation, signing and verification branches unchanged. Server contexts do not set the new client session flags and retain their original behavior. Encryption policy is not relaxed; guest encryption, Kerberos and a true `IS_NULL` server session were not verified against a live server.

Protocol basis: [MS-SMB2 3.2.4.7, Connecting to the Share](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/decadb64-9619-46e5-8892-c634213396d2) scopes mandatory 3.1.1 TREE_CONNECT signing to non-guest, non-anonymous sessions; [3.2.5.3.1, Handling a New Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c) describes guest/anonymous session signing state.

Patch paths are relative to `Dependencies/libsmb2`; use `patch -p1` there. Reverse this patch to reproduce the unmodified baseline, then reapply it before integration. Verification commands and results: `docs/m4/H16a.md` and the sibling `AMSMB2-Verify/README.md`.

```diff
diff --git a/include/libsmb2-private.h b/include/libsmb2-private.h
--- a/include/libsmb2-private.h
+++ b/include/libsmb2-private.h
@@ -175,6 +175,7 @@
         uint64_t message_id;
         uint64_t session_id;
         uint64_t async_id;
+        uint16_t session_flags;
         uint8_t *session_key;
         uint8_t session_key_size;
 
diff --git a/lib/libsmb2.c b/lib/libsmb2.c
--- a/lib/libsmb2.c
+++ b/lib/libsmb2.c
@@ -185,6 +185,7 @@
 
         smb2->message_id = 0;
         smb2->session_id = 0;
+        smb2->session_flags = 0;
         smb2->tree_id_top = 0;
         smb2->tree_id_cur = 0;
         smb2->tree_id[0] = 0xdeadbeef;
@@ -702,6 +703,8 @@
                 return;
         }
 
+        smb2->session_flags = rep->session_flags;
+
         if (rep->session_flags & SMB2_SESSION_FLAG_IS_ENCRYPT_DATA) {
                 smb2->seal = 1;
                 smb2->sign = 0;
@@ -725,7 +728,9 @@
 #endif
 
 
-        if (smb2->sign || smb2->seal || smb2->dialect == SMB2_VERSION_0311) {
+        /* Guest and anonymous sessions have no usable signing key. */
+        if (!(smb2->session_flags & (SMB2_SESSION_FLAG_IS_GUEST | SMB2_SESSION_FLAG_IS_NULL)) &&
+            (smb2->sign || smb2->seal || smb2->dialect == SMB2_VERSION_0311)) {
                 uint8_t zero_key[SMB2_KEY_SIZE] = {0};
                 int have_valid_session_key = 1;
 
@@ -2622,6 +2627,7 @@
         }
         close(smb2->fd);
         smb2->fd = SMB2_INVALID_SOCKET;
+        smb2->session_flags = 0;
 }
 
 static void
diff --git a/lib/pdu.c b/lib/pdu.c
--- a/lib/pdu.c
+++ b/lib/pdu.c
@@ -676,8 +676,9 @@
                         /* TODO - care about check reply failures? */
                 }
                 smb2_encode_header(smb2, &p->out.iov[0], &p->header);
-                if (smb2->sign ||
-                    (p->header.command == SMB2_TREE_CONNECT && smb2->dialect == SMB2_VERSION_0311 && !smb2->seal)) {
+                if (!(smb2->session_flags & (SMB2_SESSION_FLAG_IS_GUEST | SMB2_SESSION_FLAG_IS_NULL)) &&
+                    (smb2->sign ||
+                     (p->header.command == SMB2_TREE_CONNECT && smb2->dialect == SMB2_VERSION_0311 && !smb2->seal))) {
                         if (smb2_pdu_add_signature(smb2, p) < 0) {
                                 smb2_set_error(smb2, "Failure to add "
                                                "signature. %s",
diff --git a/lib/socket.c b/lib/socket.c
--- a/lib/socket.c
+++ b/lib/socket.c
@@ -719,7 +719,8 @@
          * setup has completed, so we can not yet verify the signature
          * of the final leg of session setup.
          */
-        if (smb2->sign &&
+        if (!(smb2->session_flags & (SMB2_SESSION_FLAG_IS_GUEST | SMB2_SESSION_FLAG_IS_NULL)) &&
+            smb2->sign &&
             (smb2->hdr.flags & SMB2_FLAGS_SIGNED) &&
             (smb2->hdr.command != SMB2_SESSION_SETUP) ) {
                 uint8_t signature[16] _U_;
```

## Security backport (2026-10-23)

Targeted upstream hardening for audit findings R4-001 to R4-004 (`docs/m6/audit-20261022/`), applied on top of the guest/anonymous signing patch above. libsmb2 was **not** upgraded as a whole: most of the ~400 later upstream commits are libdcerpc, server-side and transport (QUIC/SMB Direct) work outside the AMSMB2 client path.

The complete series, in application order, is kept as `git format-patch` files in `Patches/2026-10-23-security-backport/`. To reproduce the vendored tree: check out upstream `aff9fa6`, apply the guest patch above, then `git am Patches/2026-10-23-security-backport/*.patch`; the result is byte-identical to `Dependencies/libsmb2` (two trailing-whitespace warnings come from upstream `5e75eeb`).

| # | Upstream commit | Summary | Audit item |
| --- | --- | --- | --- |
| 1 | [`5e75eebf922b338cdb548d60cffb3b997d2a12e8`](https://github.com/sahlberg/libsmb2/commit/5e75eebf922b338cdb548d60cffb3b997d2a12e8) | Bound `smb2_add_iovector` against chained PDUs | R4-001 (iov capacity) |
| 2 | [`883e787426df52dd19206234d7278d46ac997668`](https://github.com/sahlberg/libsmb2/commit/883e787426df52dd19206234d7278d46ac997668) | NULL checks for every `smb2_add_iovector` caller | R4-001 |
| 3 | [`39d95961d7bdcdb330a9226d2f74fc40797ea5ee`](https://github.com/sahlberg/libsmb2/commit/39d95961d7bdcdb330a9226d2f74fc40797ea5ee) | Free buffers when `smb2_add_iovector` fails | R4-001 |
| 4 | [`bae5ef5d94537dcaf5fb520cfed22bb84c99e20b`](https://github.com/sahlberg/libsmb2/commit/bae5ef5d94537dcaf5fb520cfed22bb84c99e20b) | Validate untrusted lengths/offsets in PDU decoders; QUERY_DIRECTORY clears `pdu->payload` before freeing | R4-001, R4-003 |
| 5 | [`053d960087e450082b02aecd711740339ec7ad8f`](https://github.com/sahlberg/libsmb2/commit/053d960087e450082b02aecd711740339ec7ad8f) | Require a signature instead of trusting a cleared `SMB2_FLAGS_SIGNED` | R4-002 (signing) |
| 6 | [`09424faccbd377bc0bbd576f1fc20838ca483ab8`](https://github.com/sahlberg/libsmb2/commit/09424faccbd377bc0bbd576f1fc20838ca483ab8) | No zero-length pad vector; bounded iovec skip loop | R4-001 |
| 7 | [`7a970456c171152d033e4e02e540e00253aabd6a`](https://github.com/sahlberg/libsmb2/commit/7a970456c171152d033e4e02e540e00253aabd6a) | Refuse nested SMB3 transform headers | R4-001 |
| 8 | [`e94eee9465d55ed094ace2c038a8705b4822dada`](https://github.com/sahlberg/libsmb2/commit/e94eee9465d55ed094ace2c038a8705b4822dada) | Refuse plaintext once sealing keys exist; validate transform flags/SessionId/OriginalMessageSize before allocating; cap receive lengths | R4-001, R4-002 (encryption) |
| 9 | local | `decode_dirents` checks decoder errors and bounds `next_entry_offset` | R4-004 (still unfixed upstream) |

Conflict resolutions (all in files the series touches; see the patch files for the exact result):

- `lib/socket.c`, no-matching-PDU branch (commits 3, 6, 8): upstream's version depends on later cancelled-PDU and compound-ordering work that is not vendored. The existing behaviour (fail with "no matching PDU found") is kept, so the queued-padding path those commits harden is not reachable here.
- `lib/socket.c`, receive signature check (commit 5): upstream's rule — skip only NEGOTIATE, SESSION_SETUP and PDUs that arrived inside a transform, otherwise reject a missing signature — is combined with the guest/anonymous exclusion above. Upstream relies on guest sessions failing earlier because of a zero session key; the guest patch skips that derivation, so the exclusion must stay. The new final-leg SESSION_SETUP check in `lib/libsmb2.c` sits inside the guest-excluded block and needed no change.
- `lib/libsmb2.c`, `smb2_close_context` (commit 8): both `session_flags` and the new `enc_keys_ready` are reset.
- `lib/ntlmssp.c` (commit 4): upstream's offset check was taken as is.
- `lib/smb2-cmd-ioctl.c` (commit 4): upstream's checks were taken with the vendored macro names `IOV_OFFSET` / `IOVREQ_OFFSET` (upstream renamed them later in `37503b3`).

Local patch 9 (`lib/libsmb2.c`, `lib/smb2-cmd-query-directory.c`): `smb2_decode_fileidfulldirectoryinformation` rejects entries shorter than the 80-byte fixed part and fails when the name allocation fails; `decode_dirents` zeroes `fs` per entry, propagates the decoder error, requires a non-zero `next_entry_offset` to start after the current name and stay within the reply, and only then allocates and links the entry that takes ownership of the name. Entry alignment is not enforced, to stay tolerant of servers that pad differently.

Verification (2026-10-23):

- `project/Vendor/AMSMB2-Verify/Offline/offline.sh` builds the vendored tree with ASan/UBSan and feeds malformed replies: valid and invalid directory entries, a rejected QUERY_DIRECTORY fixed part, short transform frames, a transform before encryption keys exist and a plaintext reply on a sealed session. All 11 checks pass. Against the pre-backport tree (`LIBSMB2_DIR=<aff9fa6 + guest patch> OFFLINE_CFLAGS=-DOFFLINE_BASELINE`) all three groups crash: double free in `free_smb2dir` (R4-004), double free in `smb2_free_pdu` (R4-003), heap-buffer-overflow at `socket.c:415` (R4-001).
- `project/Vendor/AMSMB2-Verify/verify.sh after` and `mandatory` against the local Samba container: guest, authenticated, rejected password, empty credentials and mandatory signing all pass with exact listing and content.
- Not covered: a live server forcing encryption, a man-in-the-middle stripping `SMB2_FLAGS_SIGNED` (only the code path is covered), Kerberos, and real NAS devices.
