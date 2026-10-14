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
