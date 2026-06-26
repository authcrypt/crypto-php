<?php

declare(strict_types=1);

namespace Authcrypt\Crypto;

use RuntimeException;

/**
 * Exception thrown when encryption or decryption fails.
 */
final class EncryptionException extends RuntimeException {}
