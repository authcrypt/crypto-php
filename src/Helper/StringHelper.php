<?php

declare(strict_types=1);

namespace Authcrypt\Crypto\Helper;

use function mb_strlen;
use function mb_substr;

/**
 * Provides static methods for byte-oriented string operations.
 */
final class StringHelper
{
    /**
     * Returns the number of bytes in the given string.
     *
     * @param string|null $input The string being measured for length.
     *
     * @psalm-return int<0, max>
     */
    public static function byteLength(?string $input): int
    {
        return mb_strlen((string) $input, '8bit');
    }

    /**
     * Returns the portion of string specified by the start and length parameters.
     *
     * @param string $input The input string. Must be one character or longer.
     * @param int $start The starting position.
     * @param int|null $length The desired portion length. If not specified or `null`, there will be
     * no limit on length i.e. the output will be until the end of the string.
     *
     * @return string The extracted part of string (raw binary).
     */
    public static function byteSubstr(string $input, int $start, ?int $length = null): string
    {
        return mb_substr($input, $start, $length, '8bit');
    }
}
