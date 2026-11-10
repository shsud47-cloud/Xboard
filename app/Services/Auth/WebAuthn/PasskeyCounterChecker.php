<?php

namespace App\Services\Auth\WebAuthn;

use Webauthn\Counter\CounterChecker;
use Webauthn\CredentialRecord;
use Webauthn\Exception\CounterException;

/**
 * Synced passkeys (iCloud, Google Password Manager) always report counter 0.
 * A non-zero counter that does not increase is treated as a cloned authenticator.
 */
final class PasskeyCounterChecker implements CounterChecker
{
    public function check(CredentialRecord $credentialRecord, int $currentCounter): void
    {
        if ($currentCounter === 0 && $credentialRecord->counter === 0) {
            return;
        }

        if ($currentCounter > $credentialRecord->counter) {
            return;
        }

        throw CounterException::create(
            $currentCounter,
            $credentialRecord->counter,
            'Invalid counter.'
        );
    }
}
