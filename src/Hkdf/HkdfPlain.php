<?php

declare(strict_types=1);

namespace Authcrypt\Crypto\Hkdf;

use RuntimeException;
use SensitiveParameter;
use ValueError;
use Authcrypt\Crypto\EncryptionException;
use Authcrypt\Crypto\KdfInterface;
use Authcrypt\Crypto\Helper\StringHelper;

use function hash;
use function hash_hkdf;
use function hash_hmac_algos;
use function in_array;

/**
 * KDF that directly applies HKDF (RFC 5869) to the input secret.
 * Suitable for deriving additional keys from a high-entropy secret (random key).
 */
final readonly class HkdfPlain implements KdfInterface
{
    /**
     * @psalm-var int<0, max> $saltSize
     */
    private int $saltSize;

    /**
     * @param string $hashAlgo Hash algorithm for key derivation {@see hash_hmac_algos()}.
     * @param int|null $saltSize Required size of the dynamic salt in bytes. If `null`, it is set to the hash output length.
     *
     * @psalm-param null|int<0, max> $saltSize
     *
     * @throws RuntimeException If the hash algorithm is not supported.
     */
    public function __construct(
        private string $hashAlgo = 'sha256',
        ?int $saltSize = null,
    ) {
        if (!in_array($hashAlgo, hash_hmac_algos())) {
            throw new RuntimeException("'{$hashAlgo}' is not an allowed algorithm.");
        }

        $this->saltSize = $saltSize ?? StringHelper::byteLength(hash($this->hashAlgo, '', true));
    }

    /**
     * Derives a key using HKDF.
     *
     * @param string $secret High-entropy secret key.
     * @param int $keySize Desired key length in bytes.
     * @param string $context Application-specific context. May be empty.
     * @param string $salt Dynamic salt value. Must be exactly {@see getSaltSize()} bytes.
     *
     * @psalm-mutation-free
     *
     * @throws EncryptionException
     *
     * @return string Derived key (raw binary).
     */
    public function derive(
        #[SensitiveParameter]
        string $secret,
        int $keySize,
        string $context = '',
        string $salt = '',
    ): string {
        /** @psalm-suppress ImpureMethodCall */
        if (StringHelper::byteLength($salt) !== $this->saltSize) {
            throw new EncryptionException("Salt must be {$this->saltSize} bytes long.");
        }

        try {
            return hash_hkdf($this->hashAlgo, $secret, $keySize, $context, $salt);
        } catch (ValueError $e) {
            throw new EncryptionException($e->getMessage());
        }
    }

    /**
     * @inheritdoc
     */
    public function getSaltSize(): int
    {
        return $this->saltSize;
    }
}
