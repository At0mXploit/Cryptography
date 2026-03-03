# ── four stages of the TLS handshake (both 1.2 and 1.3) ──────────────────────
# stage 1: client and server exchange capabilities and agree on parameters
#           cipher suites, TLS version, extensions, randoms
# stage 2: certificate(s) are verified or other authentication occurs
#           in TLS 1.3 the cert is encrypted - network sniffers cannot read it
# stage 3: shared master secret is agreed upon to derive encryption keys
#           this is where key exchange algorithms like RSA or ECDHE are used
# stage 4: both sides verify no handshake messages were tampered with
#           finished messages contain a MAC over the entire handshake transcript

# ── why RSA key exchange was so dangerous ────────────────────────────────────
# with RSA key exchange in TLS 1.2:
#   attacker records all encrypted traffic now
#   later obtains RSA private key via hack, court order, NSA etc.
#   retroactively decrypts ALL past recorded sessions
#   intelligence agencies suspected of doing exactly this at scale
# this drove forward secrecy becoming a hard requirement in modern TLS

# ── how ephemeral diffie-hellman provides forward secrecy ────────────────────
# when a client connects with ECDHE:
#   server generates a FRESH ephemeral key pair just for this one session
#   ephemeral keys are used in DH exchange to derive the session key
#   server long-term RSA cert is now ONLY used to sign the handshake (auth)
#   it never touches the actual session key material
#   after connection ends the ephemeral key pair is deleted
#   result: even if RSA private key is stolen later, past sessions stay safe
#   because the ephemeral DH keys no longer exist anywhere
# this is forward secrecy - compromise of long-term keys does not affect past sessions

# ── why TLS 1.3 cannot be decrypted with just the private key ────────────────
# TLS 1.3 mandates ephemeral DH only - RSA key exchange is completely removed
# session key comes from ephemeral ECDH values that are thrown away after use
# to decrypt a TLS 1.3 session you need the actual ephemeral DH parameters
# browsers and tools can log these to a keylog file during the live session

# ── what is the NSS keylog format ────────────────────────────────────────────
# NSS key log format is a standard way to record secret DH parameters from TLS
# each line ties a secret to a specific session via the client random:
#   CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
#   SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
#   CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
#   SERVER_TRAFFIC_SECRET_0 <client_random> <secret>
# wireshark matches these by finding the client_random in the ClientHello packet
# to generate a keylog: set env var SSLKEYLOGFILE=/path/keylog.txt before browser launch
# works in firefox and chrome automatically

# ── wireshark GUI steps to decrypt TLS 1.3 with keylog file ─────────────────
# step 1: open tls3.cryptohack.org.pcapng in wireshark
#
# step 2: Edit > Preferences > Protocols > TLS
#         find the field "(Pre)-Master-Secret log filename"
#         click Browse and select keylogfile.txt
#         click OK
#
# step 3: wireshark automatically matches each session client_random
#         to the corresponding secrets in the keylog file
#         then derives all traffic keys and decrypts Application Data records
#
# step 4: type in the filter bar:  http2
#         press enter
#
# step 5: look through the DATA frames in the packet list
#         the flag will be in the decrypted HTTP response body
#         alternatively: right-click any http2 packet > Follow > TLS Stream
#         the full decrypted stream will show the flag in plaintext

# ── key difference from TLS 1.2 challenge ────────────────────────────────────
# TLS 1.2 with RSA: provide privkey.pem → wireshark decrypts ClientKeyExchange
# TLS 1.3 with ECDHE: provide keylogfile.txt → wireshark uses logged DH secrets
# the private key alone is completely useless for TLS 1.3
# because the ephemeral DH values that created the session key are already gone
