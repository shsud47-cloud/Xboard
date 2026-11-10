<?php

namespace App\Services\Auth\WebAuthn;

use RuntimeException;

class PasskeyException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly int $status = 400
    ) {
        parent::__construct($message);
    }
}
