<?php

declare(strict_types=1);

namespace Authcrypt\Crypto;

use SensitiveParameter;
use Stringable;
use Authcrypt\Crypto\Helper\StringHelper;

use function random_bytes;

/**
 * Envelope encryption (key wrapping) using a KDF to derive a Key Encryption Key (KEK)
 * and a random Data Encryption Key (DEK). The DEK is encrypted with the KEK and stored
 * together with the ciphertext.
 *
 * The cipher responsible for encrypting the actual data MUST be AEAD,
 * because the final payload contains no external authentication.
 */
final readonly class EnvelopeCryptor implements CryptorInterface
{
    private string $secret;

    private CipherInterface $kwCipher;

    /**
     * @psalm-var int<1, max>
     */
    private int $kekSize;

    /**
     * @psalm-var int<1, max>
     */
    private int $dekSize;

    /**
     * @psalm-var int<0, max>
     */
    private int $dekNonceSize;

    /**
     * @psalm-var int<0, max>
     */
    private int $dataNonceSize;

    /**
     * @psalm-var int<0, max>
     */
    private int $saltSize;

    private int $saltDekNonceLength;
    private int $wrapDekLength;
    private int $saltDekNonceWrapDekLength;
    private int $headerLength;

    /**
     * @param string|Stringable $secret The master secret (sensitive).
     * @param KdfInterface $kdf Key derivation function. Used to derive KEK from secret.
     * @param CipherInterface $cipher Cipher used to encrypt the actual data.
     * @param CipherInterface|null $kwCipher Cipher used to wrap the DEK. If not provided (or `null`),
     * the same cipher as `$cipher` is used for both data encryption and DEK wrapping.
     */
    public function __construct(
        #[SensitiveParameter]
        string|Stringable $secret,
        private KdfInterface $kdf,
        private CipherInterface $cipher,
        ?CipherInterface $kwCipher = null,
    ) {
        $this->secret = (string) $secret;

        $this->kwCipher = $kwCipher ?? $this->cipher;

        $this->kekSize = $this->kwCipher->getKeySize();
        $this->dekSize = $this->cipher->getKeySize();

        $this->dekNonceSize = $this->kwCipher->getNonceSize();
        $dekTagSize = $this->kwCipher->getOverheadSize();
        $this->dataNonceSize = $this->cipher->getNonceSize();
        $this->saltSize = $this->kdf->getSaltSize();

        $this->saltDekNonceLength = $this->saltSize + $this->dekNonceSize;
        $this->wrapDekLength = $this->dekSize + $dekTagSize;
        $this->saltDekNonceWrapDekLength = $this->saltDekNonceLength + $this->wrapDekLength;
        $this->headerLength = $this->saltDekNonceWrapDekLength + $this->dataNonceSize;
    }

    /**
     * {@inheritdoc}
     *
     * Structure: kdfSalt (saltSize) ||
     *            dekNonce (kwCipher nonce size) ||
     *            wrappedDEK (dekSize + kwCipher tag size) ||
     *            dataNonce (cipher nonce size) ||
     *            encryptedData (variable + cipher tag size)
     */
    public function encrypt(
        string $data,
        string $context = '',
    ): string {
        $kdfSalt = $this->saltSize ? random_bytes($this->saltSize) : '';
        $dek = random_bytes($this->dekSize);
        $dekNonce = $this->dekNonceSize ? random_bytes($this->dekNonceSize) : '';
        $dataNonce = $this->dataNonceSize ? random_bytes($this->dataNonceSize) : '';

        $kek = $this->kdf->derive($this->secret, $this->kekSize, $context, $kdfSalt);
        $dekWrapped = $this->kwCipher->encrypt($dek, $kek, $dekNonce);
        $dataEncrypted = $this->cipher->encrypt($data, $dek, $dataNonce);

        // kdfSalt || dekNonce || cipherdek || tag || dataNonce || ciphertext || tag
        return $kdfSalt . $dekNonce . $dekWrapped . $dataNonce . $dataEncrypted;
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $data,
        string $context = '',
    ): string {
        if (StringHelper::byteLength($data) < $this->headerLength) {
            throw new EncryptionException('Encrypted data is too short.');
        }

        $kdfSalt = $this->saltSize ? StringHelper::byteSubstr($data, 0, $this->saltSize) : '';
        $dekNonce = $this->dekNonceSize ? StringHelper::byteSubstr($data, $this->saltSize, $this->dekNonceSize) : '';
        $dekWrapped = StringHelper::byteSubstr($data, $this->saltDekNonceLength, $this->wrapDekLength);
        $dataNonce = $this->dataNonceSize ? StringHelper::byteSubstr($data, $this->saltDekNonceWrapDekLength, $this->dataNonceSize) : '';
        $dataEncrypted = StringHelper::byteSubstr($data, $this->headerLength);

        $kek = $this->kdf->derive($this->secret, $this->kekSize, $context, $kdfSalt);
        $dek = $this->kwCipher->decrypt($dekWrapped, $kek, $dekNonce);

        return $this->cipher->decrypt($dataEncrypted, $dek, $dataNonce);
    }
}
