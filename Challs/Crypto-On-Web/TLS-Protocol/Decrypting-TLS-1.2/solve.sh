# ── SOLUTION: decrypt TLS 1.2 using wireshark GUI ────────────────────────────

# ── why TLS 1.2 with RSA key exchange is weak ────────────────────────────────
# in TLS 1.2 with TLS_RSA_WITH_AES_256_GCM_SHA384:
#   1. server sends its RSA certificate in PLAINTEXT (packet 12)
#   2. client generates a random "premaster secret"
#   3. client encrypts premaster secret with server's RSA public key
#   4. client sends encrypted premaster secret in ClientKeyExchange (packet 14)
#   5. both sides derive master secret from: premaster + client_random + server_random
#   6. master secret → session keys → used to encrypt/decrypt all traffic
#
# the fatal flaw: if you have the server's RSA private key you can:
#   - decrypt the ClientKeyExchange to recover the premaster secret
#   - recompute the master secret and session keys
#   - decrypt ALL recorded traffic retroactively (any stored pcap ever)
#
# this is why TLS 1.3 removed RSA key exchange entirely
# TLS 1.3 only allows ephemeral DH - even with the private key you cannot
# decrypt past sessions because ephemeral DH keys are thrown away after use
# this property is called "forward secrecy"

# ── what is visible in plaintext in TLS 1.2 vs TLS 1.3 ──────────────────────
# TLS 1.2:
#   - Certificate sent in plaintext (packet 12) - anyone on the wire can read it
#   - ClientKeyExchange visible (packet 14)
#   - more handshake messages are unencrypted overall
# TLS 1.3:
#   - Certificate is encrypted (sent inside Application Data)
#   - no ClientKeyExchange step at all - DH params sent inside ClientHello instead
#   - saves a full network round trip = noticeably faster connections
#   - corporate network monitoring devices can no longer passively sniff certs

# ── WIRESHARK GUI STEPS (easiest method) ─────────────────────────────────────
#
# step 1: open the pcap
#   File > Open > tls2.cryptohack.org.pcapng
#
# step 2: load the RSA private key so wireshark can decrypt
#   Edit > Preferences > Protocols > TLS
#   find "RSA keys list" and click Edit (or the + button)
#   add a new entry:
#     IP address : (leave blank - matches any)
#     Port       : (leave blank - matches any)
#     Protocol   : http
#     Key File   : /path/to/privkey.pem
#     Password   : (leave blank)
#   click OK and OK
#
# step 3: wireshark now automatically:
#   - finds the ClientKeyExchange in packet 14
#   - decrypts the premaster secret using privkey.pem
#   - recomputes master secret using PRF("master secret", premaster, randoms)
#   - derives session keys and decrypts all Application Data records
#
# step 4: filter to see decrypted HTTP/2 traffic
#   type in the filter bar:  http2
#   hit enter
#
# step 5: find the flag
#   look through the HTTP/2 DATA frames in the packet list
#   click on a DATA frame > expand "HyperText Transfer Protocol 2" in middle pane
#   the decrypted HTTP response body will contain the flag
#   alternatively: right-click any http2 packet > Follow > TLS Stream
#   the flag will appear in the decrypted stream as plaintext

# ── what wireshark is doing under the hood ───────────────────────────────────
# wireshark replicates the TLS 1.2 key derivation:
#   premaster_secret = RSA_decrypt(privkey, ClientKeyExchange.encrypted_secret)
#   master_secret    = PRF(premaster_secret, "master secret",
#                          client_random + server_random)
#   session_keys     = PRF(master_secret, "key expansion",
#                          server_random + client_random)
# session_keys contains: client write key, server write key, IVs
# wireshark uses AES-256-GCM with these keys to decrypt each Application Data record
```

