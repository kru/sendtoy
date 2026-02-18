#include "types.h"
#include "../crypto/monocypher.h"
#include "../crypto/blake3.h"

// Wrapper around Monocypher and Blake3
// Ensuring we use the "Direct way" and avoid allocations.

void crypto_init(const u8* entropy, u32 len) {
    // Monocypher doesn't have global state to init, 
    // but we might need to seed a PRNG if we used one.
    // For now, this is a placeholder or for platform-specific entropy injection.
    (void)entropy;
    (void)len;
}

void crypto_keypair(u8 public_key[32], u8 private_key[32]) {
    // We need random bytes for the private key.
    // In a real implementation, we must pass safe randomness here.
    // For the skeleton, we assume the caller has filled private_key with random bytes
    // OR we should change the API to accept random bytes.
    // Let's assume private_key is ALREADY filled with entropy by the platform layer before calling this,
    // or we just derive public from private.
    
    // crypto_x25519_public_key(public_key, private_key);
    // Monocypher's key extraction:
    crypto_x25519_public_key(public_key, private_key);
}

void crypto_shared_secret(u8 shared_secret[32], const u8 my_private_key[32], const u8 their_public_key[32]) {
    crypto_x25519(shared_secret, my_private_key, their_public_key);
}

void crypto_encrypt(u8* dst, const u8* src, u32 len, const u8 key[32], const u8 nonce[24]) {
    // Encrypts to dst[0..len-1] and writes MAC to dst[len..len+15]
    crypto_aead_lock(dst, dst + len, key, nonce, NULL, 0, src, len);
}

bool crypto_decrypt(u8* dst, const u8* src, u32 len_cipher_plus_mac, const u8 key[32], const u8 nonce[24]) {
    if (len_cipher_plus_mac < 16) return false;
    
    u32 len_msg = len_cipher_plus_mac - 16;
    const u8* mac = src + len_msg;
    
    // Returns 0 on success
    if (crypto_aead_unlock(dst, mac, key, nonce, NULL, 0, src, len_msg) == 0) {
        return true;
    }
    return false;
}

void crypto_hash(u8 out[32], const u8* in, u32 len) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, in, len);
    blake3_hasher_finalize(&hasher, out, 32);
}
