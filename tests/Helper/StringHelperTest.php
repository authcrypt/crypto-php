<?php

declare(strict_types=1);

namespace Authcrypt\Crypto\Tests;

use PHPUnit\Framework\TestCase;
use Authcrypt\Crypto\Helper\StringHelper;

final class StringHelperTest extends TestCase
{
    public function byteLength(): void
    {
        $this->assertEquals(4, StringHelper::byteLength('this'));
        $this->assertEquals(6, StringHelper::byteLength('это'));
    }

    public function testSubstring(): void
    {
        $this->assertEquals('th', StringHelper::byteSubstr('this', 0, 2));
        $this->assertEquals('э', StringHelper::byteSubstr('это', 0, 2));

        $this->assertEquals('abcdef', StringHelper::byteSubstr('abcdef', 0));
        $this->assertEquals('abcdef', StringHelper::byteSubstr('abcdef', 0, null));

        $this->assertEquals('de', StringHelper::byteSubstr('abcdef', 3, 2));
        $this->assertEquals('def', StringHelper::byteSubstr('abcdef', 3));
        $this->assertEquals('def', StringHelper::byteSubstr('abcdef', 3, null));

        $this->assertEquals('cd', StringHelper::byteSubstr('abcdef', -4, 2));
        $this->assertEquals('cdef', StringHelper::byteSubstr('abcdef', -4));
        $this->assertEquals('cdef', StringHelper::byteSubstr('abcdef', -4, null));

        $this->assertEquals('', StringHelper::byteSubstr('abcdef', 4, 0));
        $this->assertEquals('', StringHelper::byteSubstr('abcdef', -4, 0));

        $this->assertEquals('это', StringHelper::byteSubstr('это', 0));
        $this->assertEquals('это', StringHelper::byteSubstr('это', 0, null));

        $this->assertEquals('т', StringHelper::byteSubstr('это', 2, 2));
        $this->assertEquals('то', StringHelper::byteSubstr('это', 2));
        $this->assertEquals('то', StringHelper::byteSubstr('это', 2, null));

        $this->assertEquals('т', StringHelper::byteSubstr('это', -4, 2));
        $this->assertEquals('то', StringHelper::byteSubstr('это', -4));
        $this->assertEquals('то', StringHelper::byteSubstr('это', -4, null));

        $this->assertEquals('', StringHelper::byteSubstr('это', 4, 0));
        $this->assertEquals('', StringHelper::byteSubstr('это', -4, 0));
    }
}
