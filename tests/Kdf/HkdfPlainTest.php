<?php

declare(strict_types=1);

namespace Authcrypt\Crypto\Tests\Kdf;

use PHPUnit\Framework\Attributes\DataProvider;
use Authcrypt\Crypto\EncryptionException;
use Authcrypt\Crypto\KdfInterface;
use Authcrypt\Crypto\Hkdf\HkdfPlain;

final class HkdfPlainTest extends AbstractKdfCase
{
    public static function dataProviderKeyValues(): iterable
    {
        yield [
            'sha256',
            '263d2461b6464bbc898ffa385f9d4c1a8f5a1cf0e2d27c4499516142e0542125',
            32,
            'test-context',
            'ae8cbb001c062cd2c00ed6956842dc4d36f5ce3e9b6b607e46e47018841b29d7',
            '7aa7df7d9bb661dde0b85518a590c89ed3941a9287b83bcdba0c8f36dee3351b',
        ];
        yield [
            'sha512',
            '84c7e9fb214e1d5d3ac6d9ae7b7af33f23355f4795831dcdb5d97093ec42d3d32b4391c7e1b2673ec5577aad934d231d24fd9e5032dd845e86e75a965eba4207',
            64,
            'test-context',
            '5a64ca7627ad8c93254123dda29e631110dea2276db55e0cf273518b367f0a0a38cb307970458cbc6e78d10d9d5b5ead975cd38a8b086ab8c776e4605ab82386',
            '3bb819de9794ac41c3e32967cefcf7b42c27e2cb870e8b452444d45ae8b400a4489922043918f3e61f43ed1762f70b9a80321839b5b3cffbe3d6937577f8787a',
        ];
        yield [
            'sha3-256',
            '983447213c2c295a72a64d95e069793b9acf4cbaef59b71a86cbc6aec4f020e4',
            32,
            'test-context',
            'aa24ea6b979b1a857d9f9dfa0dcac8a44c3f7b9ea061551529556ac70dd0cfeb',
            '20d65402d5927af272ca396070a09cd2b77f850cdda29b393f6d586ac133248b',
        ];
    }

    public static function dataProviderSaltSize(): iterable
    {
        yield ['sha256', 32];
        yield ['sha512', 64];
        yield ['sha3-256', 32];
    }

    #[DataProvider('dataProviderSaltSize')]
    public function testDefaultSaltSizeValid(string $hashAlgo, int $saltSize): void
    {
        $kdf = $this->createKdfInstance($hashAlgo);
        $this->assertSame($saltSize, $kdf->getSaltSize());
    }

    public function testSaltSizeValid(): void
    {
        $kdf1 = new HkdfPlain(saltSize: 0);
        $this->assertSame(0, $kdf1->getSaltSize());

        $kdf2 = new HkdfPlain(saltSize: 24);
        $this->assertSame(24, $kdf2->getSaltSize());
    }

    public function testInvalidSaltSizeThrowsException(): void
    {
        $kdf = new HkdfPlain(saltSize: -1);

        $this->expectException(EncryptionException::class);
        $kdf->derive('test-secret', 32, 'test-context', 'test-salt');
    }

    protected function createKdfInstance(?string $hashAlgo = null): KdfInterface
    {
        return isset($hashAlgo)
            ? new HkdfPlain(hashAlgo: $hashAlgo)
            : new HkdfPlain();
    }
}
