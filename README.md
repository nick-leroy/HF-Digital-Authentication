# Proposal: Readable Message Authentication for Amateur Radio Digital Protocols with Session Tokens and Offline Verification

Amateur radio digital modes, like most HF digital protocols, have no built-in way to prove that a message claiming to be from a particular callsign actually came from that operator. Anyone can transmit as anyone. While amateur regulations in many countries forbid encryption, they generally allow authentication methods that keep the content fully readable. This creates an opportunity to add lightweight verification without violating the "no obfuscation" rule.

The goal is to give operators a simple way to check that a message really came from the person it claims to, without changing existing protocols or hiding the text. The system should add only a small overhead, work with existing digital mode software through available APIs, and be optional—stations that don't participate still see normal readable messages.

While this proposal uses JS8Call as the primary example, the authentication scheme is designed to work with any amateur digital protocol that can transmit text messages. JS8Call's short message constraints and limited character set make it an ideal test case—if the authentication overhead is acceptable here, it will work even better with protocols that allow longer transmissions such as FT4, PSK31, RTTY, packet radio, or digital voice modes.

## Threat Model

This proposal specifically targets casual and criminal spoofers who might impersonate another operator's callsign for malicious purposes, pranks, or to cause confusion during emergency communications. The system is designed to make such impersonation significantly more difficult by requiring cryptographic knowledge and preparation rather than simply typing a different callsign.

Sophisticated state-level attackers are explicitly beyond the scope of what amateur radio operators should expect to defend against with any authentication system. Such actors have resources and capabilities that exceed what any amateur radio protocol could reasonably protect against, and attempting to do so would add unnecessary complexity that could hinder adoption.

## The Approach

The method uses a combination of short authentication tags and occasional full digital signatures, all tied to a per-session token that's proven once at the start of a QSO. This prevents casual spoofing, enables quick verification, and keeps every message fully readable.

Each participating operator would generate a public/private keypair using Ed25519, and publish the public key somewhere accessible—such as a QRZ page, club website, DNS TXT record, or central GitHub repository—along with a short fingerprint. When a QSO begins, the sender announces a session token in a signed header. Every following message's tag is computed from that token, the message text, and metadata, so tags can't be forged without having seen the signed session start.

**Why Ed25519?** This elliptic curve signature algorithm was chosen for several reasons critical to amateur radio applications: it produces compact 64-byte signatures (much smaller than RSA's 256+ bytes), has small 32-byte public keys practical for publishing in QRZ pages or DNS records, provides strong 128-bit security equivalent to AES-256, offers fast verification important for real-time operation, has simple implementation with fewer security pitfalls than ECDSA, enjoys wide support in modern cryptographic libraries, and is free from patent restrictions. For bandwidth-constrained HF digital modes, Ed25519's combination of strong security and compact size makes it far more practical than alternatives.

## Strict Canonicalization

For signing and verification to be reliable across different clients and transports, all messages are converted to a canonical form before hashing or signing. This is essential because different software implementations and transmission paths can alter message formatting in ways that would break cryptographic verification, even when the human-readable content is identical.

**Why Canonicalization is Critical**: Without standardization, the same message could appear as "Anyone near Denver?" in one application but "ANYONE NEAR DENVER?" in another (due to digital mode uppercasing), "Anyone  near  Denver?" (extra spaces from transmission), or with different line endings (\r\n vs \n). Each variation would produce completely different HMAC tags, making verification impossible despite identical content. Amateur radio's diverse software ecosystem and transmission effects make this standardization absolutely necessary for reliable authentication.

The canonicalization rules are:

1. Uppercase ASCII only — non-ASCII characters are stripped or transliterated.
2. Collapse multiple spaces into a single space.
3. Trim leading and trailing spaces.
4. Normalize line endings to \n.
5. Fields are concatenated in the exact order:
FROM:<CALLSIGN>\n
AT:<UTC-ISO>\n
ID:<MSG_ID>\n
MSG:<CANONICALIZED MESSAGE TEXT>\n

6. UTC timestamps use the format YYYY-MM-DDTHH:MM:SSZ.

This ensures that everyone verifies the same byte string even if different applications display or wrap the text differently, enabling reliable authentication across the diverse amateur radio software ecosystem.

## Session Token in Traffic

The session token is a random 16-byte value, encoded for safe transmission (Base64 without padding, or Base32/Base58 if punctuation is an issue). It is sent once at the start of a QSO in a signed "session header" frame:
KX4ABC> SESS 20250814T183000Z KFP:F5A83D1B T:5vLqZLrF3H7pJkEc SIG:Oiq2Wx48U9s3GcB7D36Pny34B4ItNeqlwDoH4i+mW4VJmZ0hE5X3QJY03BnsRZ9Hnyl9HfE8lDn+2nCSbzzzDA==

- SESS — keyword indicating this is a session header.
- 20250814T183000Z — UTC timestamp for the session start.
- KFP:F5A83D1B — 4-byte fingerprint of the public key being used this session.
- T:5vLqZLrF3H7pJkEc — session token, 128 bits of randomness, encoded in ~16 printable characters.
- SIG:… — full Ed25519 signature over (CALLSIGN || UTC || KFP || T).

This SESS frame establishes the session token and binds it to both the callsign and the specific public key being used. The fingerprint prevents session replay attacks with substituted keys. Receivers store T for the duration of the session and reject short tags that aren't linked to a valid session header.

## Subsequent Messages

Each message in the session carries:

1. The human-readable message line:
KX4ABC> MSG 01 ANYONE NEAR DENVER FOR A RELAY?
- MSG 01 is a message ID for pairing with its tag.

2. The HMAC authentication tag line:
KX4ABC> SIG48 01 20250814T183200Z B4A7C2F1E8D3
- 6-byte HMAC tag: Trunc(HMAC-SHA256(T, CALLSIGN || UTC || MSG_ID || canonicalized MSG), 6B).
- The tag proves the message came from someone who knows the session token T and matches the specific message ID.
- HMAC provides stronger authentication than simple hashing while maintaining compact size.

Because T is publicly bound to the sender's key in the signed SESS frame, anyone with the public key can verify tags without further signatures. The token changes every QSO, preventing long-term replay. Including the message ID prevents tag substitution between messages in the same session. The HMAC construction ensures that only someone with knowledge of the session token could have generated valid tags.

## Key Publishing and Discovery

For simplicity and widespread adoption, the initial implementation should focus on a single primary method:

**QRZ Pages**: Operators paste their Ed25519 public key (Base64-encoded) into their QRZ biography section with a standard format:
JS8AUTH: ed25519=AAAC4zdTeXX16htnIgReGCc8wrEcOILnK9QVESCb8W3k= FP:F5A83D1B

Additional publishing methods can be supported later:
- DNS TXT record: ham.CALLSIGN.example.com with ed25519=<Base64Key>
- GitHub repository: callsign→public key JSON files
- Club or ARRL listings: for groups that can vouch for membership

The 4-byte fingerprint (32 bits) provides sufficient collision resistance for the casual/criminal spoofing threat model while remaining short enough for easy verification and voice communication.

## Offline Signature Directory

In field operations or emergency deployments, internet access may not be available to fetch public keys. To support offline verification, a simple Signature Directory can be maintained:

- A signed text file or simple database containing callsign→public key mappings
- Updated weekly or monthly with new registrations
- Signed by a trusted maintainer whose public key is embedded in client software
- Distributed via web download, USB stick, ham mesh networks, or even HF file transfer
- Clients verify the maintainer's signature and cache the data locally

Format example:
JS8Call Authentication Directory v2025.08.14
Signed by: W1ABC (Emergency Coordinator)
KX4ABC ed25519=AAAC4zdTeXX16htnIgReGCc8wrEcOILnK9QVESCb8W3k= FP:F5A83D1B
N3CNO ed25519=BBBDk2eYYX27iuoJhSfHDd9xsGdPJMoL0aRWFTDc9Y4l= FP:A7E92F3C
...
Signature: iVBORw0KGgoAAAANSUhEUgAAAB4AAAAeCAYAAAA7MK6iAAAABHNCSVQICAgIfAhkiAAAAAlwSFlz...

This ensures authentication remains functional with no live infrastructure while keeping the complexity manageable.

## Why Session Tokens Instead of Full Signatures?

The choice to use session tokens with HMAC authentication tags rather than full Ed25519 signatures on every message is driven by the practical realities of HF digital communication:

**Bandwidth Efficiency**: Ed25519 signatures are 64 bytes, which when Base64-encoded become ~86 characters per message. In contrast, a 6-byte HMAC tag requires only ~38 characters total including metadata. On HF digital modes where every character consumes precious airtime and spectrum, this 56% reduction in overhead is significant.

**QRM Reduction**: Shorter authentication tags mean less spectrum usage and reduced interference to other stations—critical in crowded band conditions where every extra second of transmission increases collision probability.

**Readability**: A 6-byte HMAC tag with metadata adds only ~38 characters, keeping messages human-readable. An 86-character signature would dominate the visual space, making conversations difficult to follow and reducing the "eyeball compatibility" that makes amateur digital modes accessible.

**Error Recovery**: HF propagation frequently causes transmission errors. A corrupted 38-character tag has much lower probability than a corrupted 86-character signature. When corruption does occur, retransmission costs are proportionally lower.

**Practical Operation**: For manual operation, emergency situations, or voice coordination, shorter authentication strings are more practical to type, transmit, and verify over voice channels.

**Superior Replay Protection**: The session token approach actually provides better replay protection than individual signatures would. Since the session token changes every QSO and binds to a specific time and operator, old message tags become useless immediately. Individual signatures could potentially be replayed across different contacts.

**Computational Efficiency**: Verifying an HMAC is much faster than verifying an Ed25519 signature, important for resource-constrained devices or high message volumes.

**Break-Even Analysis**: For QSOs with 3 or more messages, the session token approach uses less total bandwidth than individual signatures, while providing stronger security properties.

The session header provides the cryptographic foundation with a full signature, while subsequent HMAC tags provide efficient per-message authentication. This hybrid approach optimizes for both security and the practical constraints of amateur HF operation.

## Why SIG48 is the Optimal Choice

While this proposal could use different tag lengths, SIG48 (6-byte HMAC tags) represents the optimal balance for amateur radio applications:

**SIG32 vs SIG48 Security Analysis**:
- **SIG32 (4 bytes)**: 2^32 = 4.3 billion combinations, vulnerable to GPU-based attacks averaging ~20 seconds
- **SIG48 (6 bytes)**: 2^48 = 281 trillion combinations, requiring ~65,000 years average attack time even with modern GPUs
- **Security Improvement**: The additional 2 bytes provide a 65,536x increase in security strength

**Transmission Efficiency in JS8Call**:
- **SIG32**: 35 characters = 3 frames in Normal mode (~10 seconds transmission)
- **SIG48**: 38 characters = 3 frames in Normal mode (~10 seconds transmission)
- **Key Insight**: Both SIG32 and SIG48 require identical transmission time in JS8Call since they fit within the same frame boundaries

**SIG48 vs SIG64 (Full Signatures)**:
- **SIG48**: 38 characters total overhead per message
- **SIG64**: 86 characters total overhead per message  
- **Bandwidth Savings**: SIG48 uses 56% less bandwidth than full signatures while providing adequate security for the amateur radio threat model
- **Break-Even Point**: Session token approach with SIG48 becomes more efficient than SIG64 for QSOs with 3+ messages

**Future-Proof Design**: 
- SIG48 provides comfortable security margins against advances in computing power
- Eliminates the need for complex session timeout calculations based on cryptographic concerns
- Simplifies security analysis - SIG48 is simply secure against brute force attacks, period

**Practical Benefits**:
- No additional transmission time cost compared to SIG32
- Vastly superior security with minimal overhead increase
- Removes timing-based security considerations from protocol design
- Maintains readability while providing enterprise-grade authentication strength

For amateur radio digital modes, SIG48 delivers maximum security benefit with essentially zero additional cost, making it the clear choice for standardization.

## Session Management and Error Handling

**Session Lifecycle**: 
- Sessions are valid from the SESS timestamp until 1-2 hours later or until a new SESS is seen from the same callsign
- If a station misses the SESS frame, messages from that session simply show as "unverified"
- No complex recovery mechanisms - simplicity encourages adoption

**Security Analysis of Session Timeout**: While longer sessions might seem like a security concern, the practical attack constraints make session lifetime less critical than initial intuition suggests. For a 6-byte HMAC tag (SIG48):

- **Brute Force Difficulty**: 2^48 = 281 trillion possible values, requiring ~140 trillion attempts on average
- **Attack Timeline**: Even with specialized hardware performing 1 billion HMAC operations per second, average break time exceeds 4,500 years
- **Real-World Impossibility**: No practical attack exists against SIG48 tags within amateur radio operational timeframes
- **Session Timeout Conclusion**: With SIG48, session timeouts are purely a matter of operational convenience rather than cryptographic necessity

For amateur radio's target threat model, the session timeout is primarily a matter of operator convenience rather than cryptographic security. The real protection comes from the difficulty of performing real-time HMAC attacks within typical QSO message timing.

**Verification Display**:
- ✓ Verified: Message tag validates against known session and public key
- ? Unverified: No session established, key not found, or tag mismatch
- No complex error states or warnings - keep the UI simple

**Backward Compatibility**:
- Stations without authentication support see normal readable messages
- Authenticated and unauthenticated messages can coexist in the same QSO
- No protocol changes to existing JS8Call operation

## Questions for the Community

- Should the standard include SIG32 (4 bytes) as a "fast mode" option for extremely bandwidth-constrained situations?
- How often should SESS headers be retransmitted during long QSOs?
- Who should maintain the offline directory for emergency use?
- Should we include frequency/band information in the signed data to prevent cross-band replay?
- For very short QSOs (1-2 messages), should we offer a "SIG64" mode using full signatures instead of session tokens?

The focus remains on providing higher assurance of message authenticity while maintaining the simplicity that makes amateur radio accessible. Sophisticated attackers will always find ways around any amateur system, but this approach makes impersonation significantly more difficult for the common threat scenarios operators actually face.
