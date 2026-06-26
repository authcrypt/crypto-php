<?php

declare(strict_types=1);

namespace Authcrypt\Crypto\Tests;

use RuntimeException;
use stdClass;
use PHPUnit\Framework\TestCase;
use Authcrypt\Crypto\CryptorInterface;
use Authcrypt\Crypto\EncryptionException;
use Authcrypt\Crypto\VersionedCryptor;

final class VersionedCryptorTest extends TestCase
{
    public function testEncryptPrependsVersionAndDelegates(): void
    {
        $plaintext = 'test-plain-data';
        $context = 'test-context';
        $v = 'v1';

        $cryptor = $this->createMock(CryptorInterface::class);
        $cryptor->expects($this->once())
            ->method('encrypt')
            ->with($plaintext, $context)
            ->willReturn('encrypted-payload');

        $versioned = new VersionedCryptor(cryptors: [$v => $cryptor], currentVersion: $v);
        $result = $versioned->encrypt($plaintext, $context);

        $this->assertSame($v . 'encrypted-payload', $result);
    }

    public function testDecryptExtractsVersionAndCallsCorrectCryptor(): void
    {
        $plaintext = 'test-plain-data';
        $context = 'test-context';

        $encryptedPayload = 'encrypted-part';
        $fullData = 'v2' . $encryptedPayload;

        $cryptorV2 = $this->createMock(CryptorInterface::class);
        $cryptorV2->expects($this->once())
            ->method('decrypt')
            ->with($encryptedPayload, $context)
            ->willReturn($plaintext);

        $versioned = new VersionedCryptor(cryptors: ['v2' => $cryptorV2], currentVersion: 'v2');
        $result = $versioned->decrypt($fullData, $context);

        $this->assertSame($plaintext, $result);
    }

    public function testEncryptDecryptDifferentVersions(): void
    {
        $plaintext = 'test-plain-data';

        $cryptorV1 = $this->createMock(CryptorInterface::class);
        $cryptorV1->method('encrypt')->willReturn('encrypted_data_v1');
        $cryptorV1->method('decrypt')->willReturn($plaintext);

        $cryptorV2 = $this->createMock(CryptorInterface::class);
        $cryptorV2->method('encrypt')->willReturn('encrypted_data_v2');
        $cryptorV2->method('decrypt')->willReturn($plaintext);

        $versionedCryptor = new VersionedCryptor(cryptors: [
            'v1' => $cryptorV1,
            'v2' => $cryptorV2,
        ], currentVersion: 'v2');

        $encryptedDataV1 = 'v1' . $cryptorV1->encrypt($plaintext);
        $encryptedDataV2 = 'v2' . $cryptorV2->encrypt($plaintext);

        $decryptedDataV1 = $versionedCryptor->decrypt($encryptedDataV1);
        $decryptedDataV2 = $versionedCryptor->decrypt($encryptedDataV2);

        $this->assertSame($plaintext, $decryptedDataV1);
        $this->assertSame($plaintext, $decryptedDataV2);
    }

    public function testContextPassedToUnderlyingCryptor(): void
    {
        $context = 'test-context';

        $cryptor = $this->createMock(CryptorInterface::class);
        $cryptor->expects($this->once())
            ->method('encrypt')
            ->with('data', $context)
            ->willReturn('encrypted');

        $cryptor->expects($this->once())
            ->method('decrypt')
            ->with('encrypted', $context)
            ->willReturn('data');

        $versioned = new VersionedCryptor(cryptors: ['v1' => $cryptor], currentVersion: 'v1');

        $encrypted = $versioned->encrypt('data', $context);
        $decrypted = $versioned->decrypt($encrypted, $context);

        $this->assertSame('data', $decrypted);
    }

    public function testVersionSizeWorks(): void
    {
        $plaintext = 'test-plain-data';
        $version = 'v1';

        $cryptor = $this->createMock(CryptorInterface::class);
        $cryptor->method('encrypt')
            ->with($plaintext)
            ->willReturn('encrypted');
        $cryptor->method('decrypt')
            ->with('encrypted')
            ->willReturn($plaintext);

        $versioned = new VersionedCryptor(
            cryptors: [$version => $cryptor],
            currentVersion: $version,
            versionSize: 2
        );
        $encrypted = $versioned->encrypt($plaintext);
        $decrypted = $versioned->decrypt($encrypted);

        $this->assertSame($plaintext, $decrypted);
        $this->assertSame($version . 'encrypted', $encrypted);
    }

    public function testIntegerKeyIsNormalizedToStringAndLengthChecked(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor(
            cryptors: [12 => $this->createMock(CryptorInterface::class)],
            currentVersion: '123',
            versionSize: 3,
        );
    }

    public function testConstructThrowsWhenCurrentVersionNotRegistered(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor(cryptors: ['v1' => $this->createMock(CryptorInterface::class)], currentVersion: 'v2');
    }

    public function testConstructorValidationThrows(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor(cryptors: [], currentVersion: 'v1');
    }

    public function testConstructorThrowsExceptionWhenCryptorNotInstanceOfInterface(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor(cryptors: ['v1' => new stdClass()], currentVersion: 'v1');
    }

    public function testConstructorThrowsExceptionWhenVersionSizeLessThanOne(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor(cryptors: ['v1' => $this->createMock(CryptorInterface::class)], currentVersion: 'v1', versionSize: 0);
    }

    public function testConstructorThrowsExceptionWhenVersionLengthMismatch(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor(cryptors: ['v1' => $this->createMock(CryptorInterface::class)], currentVersion: 'v1', versionSize: 3);
    }

    public function testDecryptThrowsExceptionWhenDataTooShort(): void
    {
        $cryptor = $this->createMock(CryptorInterface::class);
        $versionedCryptor = new VersionedCryptor(cryptors: ['v1' => $cryptor], currentVersion: 'v1', versionSize: 2);

        $this->expectException(EncryptionException::class);
        $versionedCryptor->decrypt('x', 'secret');
    }

    public function testDecryptThrowsExceptionWhenVersionNotFound(): void
    {
        $versionedCryptor = new VersionedCryptor(cryptors: ['v1' => $this->createMock(CryptorInterface::class)], currentVersion: 'v1');

        $this->expectException(EncryptionException::class);
        $versionedCryptor->decrypt('v2' . 'test-plain-data', 'test-secret');
    }

    public function testDecryptInvalidData(): void
    {
        $cryptor = $this->createMock(CryptorInterface::class);
        $cryptor->method('decrypt')->willThrowException(new EncryptionException());

        $versionedCryptor = new VersionedCryptor(cryptors: ['v1' => $cryptor], currentVersion: 'v1');

        $this->expectException(EncryptionException::class);
        $versionedCryptor->decrypt('v1' . 'test-plain-data', 'test-secret');
    }
}
