# Application‑Level Encryption for PHP

This package provides a modern, authenticated encryption layer built on AEAD ciphers. It is designed for:

- Application‑Level Encryption (ALE) and protection of objects in storage.
- Field‑level encryption in databases.
- Client‑Side Encryption for cloud storage.
- Long‑term data storage with the ability to upgrade cryptographic algorithms.


## Requirements

- PHP 8.2 - 8.5.
- `hash` PHP extension.
- `openssl` PHP extension - optional.
- `sodium` PHP extension - optional.


## Installation

The package could be installed with [Composer](https://getcomposer.org):

```shell
composer require authcrypt/crypto-php
```


## Quick Start

```php
use Authcrypt\Crypto\KdfCryptor;
use Authcrypt\Crypto\Cipher\SodiumAeadCipher;
use Authcrypt\Crypto\Hkdf\HkdfExtended;

$secret = hex2bin('0123456789abcdef...');
$kdf = new HkdfExtended();
$cipher = new SodiumAeadCipher();

$cryptor = new KdfCryptor(
    secret: $secret,
    kdf: $kdf,
    cipher: $cipher,
);

$context = 'application-specific-context';

$encrypted = $cryptor->encrypt('secret data', $context);
$data = $cryptor->decrypt($encrypted, $context);
```


## Cryptors

All cryptors implement `CryptorInterface` and are responsible for the overall encryption flow.
They differ in how the data encryption key (`DEK`) is obtained and how the ciphertext is structured.


### `KdfCryptor`

`KDF`‑based encryption (single key derived per message, no key wrapping).  
A fresh Data Encryption Key (`DEK`) is derived from the secret and the provided context using the configured `KDF`.
If the configured `KDF` requires a salt, a random salt is generated for each message and prepended to the ciphertext.

Output structure:
```
kdfSalt (optional) || nonce || encryptedData (with tag)

```


### `EnvelopeCryptor`

Envelope encryption (key wrapping) using a `KDF` to derive a Key Encryption Key (`KEK`)
and a random Data Encryption Key (`DEK`). The `DEK` is wrapped with the `KEK` and stored
alongside the ciphertext. The `DEK` is used to encrypt the actual data.

The `DEK` wrap cipher can be specified separately (e.g., `OpenSSLWrapCipher`); if omitted, the data cipher is used for wrapping as well.

Output structure:
```
kdfSalt || dekNonce || wrappedDEK (with tag) || dataNonce || encryptedData (with tag)
```


### `VersionedCryptor`

Wraps multiple cryptors and adds a fixed‑length version prefix to every ciphertext.

Output structure:
```
version (fixed length) || encrypted payload from underlying cryptor
```


## Key Derivation

The package provides two HKDF‑based KDF implementations (RFC 5869), both suitable for high‑entropy secrets (random keys).


### `HkdfExtended`

Directly applies `HKDF` to the input secret. Suitable when the secret is already a strong random key (32 bytes or more).

This implementation satisfies the **KDF Security** requirements (resistance to key extraction and key expansion attacks) as defined in the `HKDF` specification.

`HkdfExtended` supports static salt for domain separation, ensuring that keys derived for different contexts remain distinct even when the same secret is used. It also provides dynamic salt for per‑message randomness, which is enabled by default. When dynamic salt is disabled, the caller must supply a unique context for each derivation to prevent key reuse.


### `HkdfPlain`

A simpler variant that applies `HKDF` without a static salt.
This is suitable when you do not need additional domain separation, or when the secret itself is already adequately randomised.

When salt is disabled, the caller must supply a unique context per encryption.


## Ciphers

The package provides two backends: `OpenSSL` and `Sodium` (`libsodium`).


### SodiumAeadCipher

Uses `Sodium`'s high‑performance `AEAD` ciphers. Supports the following algorithms:

- `AES-256-GCM` – requires hardware `AES‑NI` support.
- `CHACHA20-POLY1305-IETF` - **default**
- `XCHACHA20-POLY1305-IETF`

Note: `AES‑256‑GCM` with `Sodium` requires CPU support for AES instructions (`AES‑NI`).


### OpenSSLAeadCipher

Uses `OpenSSL`'s `AEAD` ciphers. Supports the following algorithms:

- `AES-128-GCM`
- `AES-192-GCM`
- `AES-256-GCM`
- `CHACHA20-POLY1305` (`IETF` variant, 12‑byte nonce) - **default**


### OpenSSLWrapCipher

A dedicated cipher for key wrapping (RFC 5649 `AES‑KW`). This cipher should only be used inside `EnvelopeCryptor` for wrapping `DEKs`, not for general‑purpose encryption.
Allowed algorithms:

- `AES-128-WRAP`
- `AES-192-WRAP`
- `AES-256-WRAP` - **default**


## Examples

### User data encryption

Use this when each entity (user, record, document) has a natural unique identifier. The context includes that identifier, so no dynamic salt is needed, making the ciphertext shorter.

```php
use Authcrypt\Crypto\KdfCryptor;
use Authcrypt\Crypto\Cipher\SodiumAeadCipher;
use Authcrypt\Crypto\Hkdf\HkdfExtended;

$staticSalt = hex2bin(getenv('APP_STATIC_SALT')); // must be exactly 32 bytes for SHA‑256
$kdf = new HkdfExtended(
    hashStaticSalt: $staticSalt,
    saltSize: 0, // disabled – rely on unique context
);
$cipher = new SodiumAeadCipher('AES-256-GCM');

$secret = hex2bin(getenv('MASTER_ENCRYPTION_KEY'));
$cryptor = new KdfCryptor(
    secret: $secret,
    kdf: $kdf,
    cipher: $cipher,
);

$userId = 12345;
$context = "user_data_{$userId}";

$encrypted = $cryptor->encrypt('sensitive user data', $context);
$decrypted = $cryptor->decrypt($encrypted, $context);
```

### Static context encryption

Use this when data does not have a natural unique identifier. The dynamic salt provides per‑message randomness.

```php
use Authcrypt\Crypto\KdfCryptor;
use Authcrypt\Crypto\Cipher\SodiumAeadCipher;
use Authcrypt\Crypto\Hkdf\HkdfExtended;

$staticSalt = hex2bin(getenv('APP_STATIC_SALT')); // must be exactly 32 bytes for SHA‑256
$kdf = new HkdfExtended(
    hashStaticSalt: $staticSalt,
    saltSize: 32, // dynamic salt enabled (default)
);
$cipher = new SodiumAeadCipher('AES-256-GCM');

$secret = hex2bin(getenv('MASTER_ENCRYPTION_KEY'));
$cryptor = new KdfCryptor(
    secret: $secret,
    kdf: $kdf,
    cipher: $cipher,
);

$context = 'app_config_v1';

$encrypted = $cryptor->encrypt('sensitive configuration', $context);
$decrypted = $cryptor->decrypt($encrypted, $context);
```

### Envelope encryption for long‑term storage

Use `EnvelopeCryptor` when you may need to rotate the master key without re‑encrypting all data.
The `DEK` is independent of the master key – only the wrapped `DEK` needs to be re‑encrypted.

```php
use Authcrypt\Crypto\EnvelopeCryptor;
use Authcrypt\Crypto\Cipher\OpenSSLAeadCipher;
use Authcrypt\Crypto\Cipher\OpenSSLWrapCipher;
use Authcrypt\Crypto\Hkdf\HkdfExtended;

$dataCipher = new OpenSSLAeadCipher('AES-256-GCM');
$wrapCipher = new OpenSSLWrapCipher('AES-256-WRAP');

$cryptor = new EnvelopeCryptor(
    secret: $secret,
    kdf: $kdf,
    cipher: $dataCipher,
    kwCipher: $wrapCipher, // if omitted, $dataCipher is used for wrapping 
);

$encrypted = $cryptor->encrypt('archive data', $context);
$decrypted = $cryptor->decrypt($encrypted, $context);
```

### Algorithm Migration with VersionedCryptor

Gradually upgrade encryption algorithms while keeping old ciphertexts readable.

```php
use Authcrypt\Crypto\KdfCryptor;
use Authcrypt\Crypto\VersionedCryptor;

$oldCryptor = new KdfCryptor($secret, $oldKdf, $oldCipher);
$newCryptor = new KdfCryptor($secret, $newKdf, $newCipher);

$versioned = new VersionedCryptor(
    cryptors: [
        'v1' => $oldCryptor,
        'v2' => $newCryptor,
    ],
    currentVersion: 'v2', // new encryptions use v2
);

// Decryption automatically detects the version from the prefix
$decrypted = $versioned->decrypt($oldCiphertext, $context);
```


## Documentation

- [Internals](docs/internals.md)

## License

MIT
