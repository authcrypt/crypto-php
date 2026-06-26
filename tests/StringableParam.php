<?php

declare(strict_types=1);

namespace Authcrypt\Crypto\Tests;

use SensitiveParameter;
use Stringable;

final readonly class StringableParam implements Stringable
{
    public function __construct(
        #[SensitiveParameter]
        private string $value,
    ) {}

    public function __toString(): string
    {
        return $this->value;
    }
}
