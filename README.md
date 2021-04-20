# Vortex
## What is Vortex
Robust security scheme for all your data transportation needs, with real time key calculation based AES encryption. No key storage. No key exchange.

## How is this achieved?
Majority of security attacks against encrypted data during transportation happen around key storage or key exchange. For a fast symmetric encryption scheme like AES, this is even more crucial. To mitigate the side attacks, what if the keys and initial vector are generated in real time? What if the key generation is based on well known information for an individual connection, so there's no need for exchange of information? Vortex provides both features for AES key and initial vector generation, so your system no longer needs to store or transmit any secret.

## Is it safe?
Is a remote attack to Vortex possible? The short answer is no. Vortex uses Keccak, the base of SHA-3 hashing, to create real time encryption keys and initial vectors. To break the cipher, as there's no secret exchange, the attacker has to gather all information used for Keccak hashing and apply them in the correct digest order. Vortex uses unique information per traffic to generate keys for each traffic stream. This means the attacker needs to get physical access to the network, and be aware of our unique scrambling method to be able to reconstruct the unique information necessary. This is easily preventable.
