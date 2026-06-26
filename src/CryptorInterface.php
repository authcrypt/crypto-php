<?php

declare(strict_types=1);

namespace Authcrypt\Crypto;

/**
 * Interface for high-level encryption/decryption.
 * Implementations receive the secret via the constructor.
 */
interface CryptorInterface
{
    /**
     * Encrypts the given data using the secret and context string.
     *
     * @param string $data Plaintext to encrypt.
     * @param string $context Unique per-encryption context string. Must match during decryption.
     *
     * @throws EncryptionException If encryption fails.
     *
     * @return string Encrypted payload.
     */
    public function encrypt(
        string $data,
        string $context = '',
    ): string;

    /**
     * Decrypts the given data using the secret and context string.
     *
     * @param string $data Encrypted payload to decrypt.
     * @param string $context Context string that was used during encryption.
     *
     * @throws EncryptionException If decryption fails.
     *
     * @return string Decrypted plaintext.
     */
    public function decrypt(
        string $data,
        string $context = '',
    ): string;
}
