<?php

namespace App\Services\Auth\WebAuthn;

use App\Models\User;
use App\Models\WebAuthnChallenge;
use App\Models\WebAuthnCredential;
use App\Services\Plugin\HookManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Paragonie\ConstantTime\Base64UrlSafe;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Symfony\Component\Serializer\SerializerInterface;

class WebAuthnService
{
    public const MAX_PASSKEYS = 10;

    private const ALLOWED_TRANSPORTS = ['usb', 'nfc', 'ble', 'hybrid', 'internal', 'smart-card'];

    private SerializerInterface $serializer;

    private AuthenticatorAttestationResponseValidator $attestationValidator;

    private AuthenticatorAssertionResponseValidator $assertionValidator;

    public function __construct()
    {
        $attestation = new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
        ]);
        $this->serializer = (new WebauthnSerializerFactory($attestation))->create();

        $ceremony = new CeremonyStepManagerFactory();
        $ceremony->setAllowedOrigins($this->origins());
        $ceremony->setCounterChecker(new PasskeyCounterChecker());
        $httpRpIds = [];
        foreach ($this->origins() as $origin) {
            $scheme = parse_url($origin, PHP_URL_SCHEME);
            $host = parse_url($origin, PHP_URL_HOST);
            if ($scheme === 'http' && is_string($host) && $host !== '') {
                $httpRpIds[] = $host;
            }
        }
        if ($httpRpIds !== []) {
            $ceremony->setSecuredRelyingPartyId(array_values(array_unique($httpRpIds)));
        }

        $this->attestationValidator = AuthenticatorAttestationResponseValidator::create(
            $ceremony->creationCeremony()
        );
        $this->assertionValidator = AuthenticatorAssertionResponseValidator::create(
            $ceremony->requestCeremony()
        );
    }

    /**
     * @return array{enabled: bool, available: bool}
     */
    public function status(?string $email, bool $forAdmin): array
    {
        $enabled = $this->credentialQuery($forAdmin)->exists();
        if ($email === null || $email === '') {
            return ['enabled' => $enabled, 'available' => $enabled];
        }

        $user = $this->findEligibleUser($email, $forAdmin);

        return [
            'enabled' => $enabled,
            'available' => $user !== null && $user->passkeys()->exists(),
        ];
    }

    /**
     * @return array{ok: true, challenge: string, options: array<string, mixed>}
     */
    public function loginOptions(?string $email, bool $forAdmin): array
    {
        $this->purgeExpiredChallenges();
        $user = null;
        $allow = [];
        if ($email !== null && $email !== '') {
            $user = $this->findEligibleUser($email, $forAdmin);
            if ($user === null || !$user->passkeys()->exists()) {
                throw new PasskeyException('用户不存在或未注册通行钥匙');
            }
            $allow = $this->allowCredentials($user);
        } elseif ($forAdmin && !$this->credentialQuery(true)->exists()) {
            throw new PasskeyException('用户不存在或未注册通行钥匙');
        } elseif (!$forAdmin && !$this->credentialQuery(false)->exists()) {
            throw new PasskeyException('尚未注册通行钥匙');
        }

        $options = PublicKeyCredentialRequestOptions::create(
            random_bytes(32),
            $this->rpId(),
            $allow,
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            $this->timeoutMs(),
        );

        return $this->storeChallenge(WebAuthnChallenge::CEREMONY_LOGIN, $options, $user);
    }

    /**
     * @param  array<string, mixed>  $credential
     */
    public function login(array $credential, string $challenge, ?string $email, bool $forAdmin): User
    {
        $stored = $this->consumeChallenge($challenge, WebAuthnChallenge::CEREMONY_LOGIN);
        /** @var PublicKeyCredentialRequestOptions $options */
        $options = $this->serializer->denormalize(
            json_decode($stored, true, 512, JSON_THROW_ON_ERROR),
            PublicKeyCredentialRequestOptions::class,
            'json'
        );

        $emailUser = null;
        if ($email !== null && $email !== '') {
            $emailUser = $this->findEligibleUser($email, $forAdmin);
            if ($emailUser === null) {
                throw new PasskeyException('用户不存在或未注册通行钥匙');
            }
        }

        $publicKeyCredential = $this->loadPublicKeyCredential($credential);
        $response = $publicKeyCredential->response;
        if (!$response instanceof AuthenticatorAssertionResponse) {
            throw new PasskeyException('通行钥匙登录失败');
        }

        $credentialId = Base64UrlSafe::encodeUnpadded($publicKeyCredential->rawId);
        $storedCredential = WebAuthnCredential::query()->where('credential_id', $credentialId)->first();
        if ($storedCredential === null) {
            throw new PasskeyException('通行钥匙登录失败');
        }
        if ($emailUser !== null && (int) $storedCredential->user_id !== (int) $emailUser->id) {
            throw new PasskeyException('通行钥匙登录失败');
        }

        $record = $this->recordFromModel($storedCredential);
        $userHandle = $emailUser !== null ? $this->userHandle($emailUser) : null;

        try {
            $updated = $this->assertionValidator->check(
                $record,
                $response,
                $options,
                $this->rpId(),
                $userHandle
            );
        } catch (PasskeyException $e) {
            throw $e;
        } catch (Throwable $e) {
            Log::info('Passkey login rejected', ['reason' => $e->getMessage()]);
            throw new PasskeyException('通行钥匙登录失败');
        }

        $user = User::query()->find($storedCredential->user_id);
        if ($user === null) {
            throw new PasskeyException('通行钥匙登录失败');
        }
        if ($user->banned) {
            throw new PasskeyException(__('Your account has been suspended'));
        }
        if ($forAdmin && !$user->is_admin) {
            throw new PasskeyException('该账号不能登录管理后台', 403);
        }

        $this->persistRecord($storedCredential, $updated, $storedCredential->transports ?? []);
        $storedCredential->last_used_at = time();
        $storedCredential->save();

        $user->last_login_at = time();
        $user->save();
        HookManager::call('user.login.after', $user);

        return $user;
    }

    /**
     * @return array{ok: true, challenge: string, options: array<string, mixed>}
     */
    public function registerOptions(User $user): array
    {
        if ($user->passkeys()->count() >= self::MAX_PASSKEYS) {
            throw new PasskeyException('通行钥匙数量已达上限');
        }
        $this->purgeExpiredChallenges();

        $handle = $this->userHandle($user);
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($this->rpName(), $this->rpId()),
            PublicKeyCredentialUserEntity::create($user->email, $handle, $user->email),
            random_bytes(32),
            [
                PublicKeyCredentialParameters::createPk(-7),
                PublicKeyCredentialParameters::createPk(-257),
            ],
            AuthenticatorSelectionCriteria::create(
                null,
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $this->allowCredentials($user),
            $this->timeoutMs(),
        );

        return $this->storeChallenge(WebAuthnChallenge::CEREMONY_REGISTER, $options, $user);
    }

    /**
     * @param  array<string, mixed>  $credential
     * @param  array<int, string>  $transports
     */
    public function register(User $user, array $credential, string $challenge, string $name, array $transports): WebAuthnCredential
    {
        if ($user->passkeys()->count() >= self::MAX_PASSKEYS) {
            throw new PasskeyException('通行钥匙数量已达上限');
        }

        $stored = $this->consumeChallenge($challenge, WebAuthnChallenge::CEREMONY_REGISTER, $user->id);
        /** @var PublicKeyCredentialCreationOptions $options */
        $options = $this->serializer->denormalize(
            json_decode($stored, true, 512, JSON_THROW_ON_ERROR),
            PublicKeyCredentialCreationOptions::class,
            'json'
        );

        $publicKeyCredential = $this->loadPublicKeyCredential($credential);
        $response = $publicKeyCredential->response;
        if (!$response instanceof AuthenticatorAttestationResponse) {
            throw new PasskeyException('注册失败');
        }

        try {
            $record = $this->attestationValidator->check($response, $options, $this->rpId());
        } catch (Throwable $e) {
            Log::info('Passkey registration rejected', ['reason' => $e->getMessage()]);
            throw new PasskeyException('注册失败');
        }

        if (!hash_equals($this->userHandle($user), $record->userHandle)) {
            throw new PasskeyException('注册失败');
        }

        $credentialId = Base64UrlSafe::encodeUnpadded($record->publicKeyCredentialId);
        if (WebAuthnCredential::query()->where('credential_id', $credentialId)->exists()) {
            throw new PasskeyException('这枚通行钥匙已经注册过');
        }

        $transports = $this->sanitizeTransports(array_merge($transports, $response->transports));
        $model = new WebAuthnCredential();
        $model->user_id = $user->id;
        $model->credential_id = $credentialId;
        $model->name = $this->sanitizeName($name);
        $model->transports = $transports;
        $model->aaguid = $record->aaguid->toRfc4122();
        $this->persistRecord($model, $record, $transports);
        $model->save();

        return $model;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function list(User $user): array
    {
        return $user->passkeys()
            ->orderBy('id')
            ->get()
            ->map(function (WebAuthnCredential $credential) {
                return [
                    'id' => $credential->id,
                    'name' => $credential->name,
                    'created' => (int) $credential->getRawOriginal('created_at'),
                    'last_used_at' => $credential->last_used_at,
                    'backed_up' => (bool) $credential->backup_state,
                ];
            })
            ->all();
    }

    public function delete(User $user, int $id): void
    {
        $credential = $user->passkeys()->where('id', $id)->first();
        if ($credential === null) {
            throw new PasskeyException('通行钥匙不存在');
        }
        $credential->delete();
    }

    public function userHandle(User $user): string
    {
        $key = (string) config('app.key');
        if ($key === '') {
            throw new PasskeyException('通行钥匙未正确配置', 500);
        }

        return substr(hash_hmac('sha256', 'xboard-passkey-user:' . $user->id, $key, true), 0, 32);
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function allowCredentials(User $user): array
    {
        $descriptors = [];
        foreach ($user->passkeys()->get() as $credential) {
            $transports = $this->sanitizeTransports(array_merge(
                $credential->transports ?? [],
                [
                    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_INTERNAL,
                    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_HYBRID,
                ]
            ));
            $descriptors[] = PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Base64UrlSafe::decodeNoPadding($credential->credential_id),
                $transports
            );
        }

        return $descriptors;
    }

    /**
     * @param  array<int, mixed>  $transports
     * @return array<int, string>
     */
    private function sanitizeTransports(array $transports): array
    {
        $clean = [];
        foreach ($transports as $transport) {
            if (!is_string($transport)) {
                continue;
            }
            $transport = strtolower(trim($transport));
            if (in_array($transport, self::ALLOWED_TRANSPORTS, true)) {
                $clean[$transport] = $transport;
            }
        }

        return array_values($clean);
    }

    private function sanitizeName(string $name): string
    {
        $name = trim(strip_tags($name));
        if ($name === '') {
            $name = '本机';
        }

        return mb_substr($name, 0, 64);
    }

    /**
     * @return array{ok: true, challenge: string, options: array<string, mixed>}
     */
    private function storeChallenge(string $ceremony, PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options, ?User $user): array
    {
        /** @var array<string, mixed> $json */
        $json = $this->serializer->normalize($options, 'json');
        // Omit an empty allowCredentials list. Dee Panel does this, and it is what
        // makes desktop Chrome show the system passkey dialog with the phone QR.
        foreach (['allowCredentials', 'excludeCredentials'] as $key) {
            if (isset($json[$key]) && $json[$key] === []) {
                unset($json[$key]);
            }
        }
        WebAuthnChallenge::query()->create([
            'challenge' => $json['challenge'],
            'user_id' => $user?->id,
            'ceremony' => $ceremony,
            'options' => json_encode($json, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'expires_at' => time() + $this->ttl(),
            'created_at' => time(),
        ]);

        return [
            'ok' => true,
            'challenge' => $json['challenge'],
            'options' => $json,
        ];
    }

    private function consumeChallenge(string $challenge, string $ceremony, ?int $userId = null): string
    {
        $options = DB::transaction(function () use ($challenge, $ceremony, $userId) {
            $row = WebAuthnChallenge::query()
                ->where('challenge', $challenge)
                ->where('ceremony', $ceremony)
                ->lockForUpdate()
                ->first();
            if ($row === null || $row->expires_at < time()) {
                if ($row !== null) {
                    $row->delete();
                }

                return null;
            }
            if ($userId !== null && (int) $row->user_id !== $userId) {
                $row->delete();

                return null;
            }
            $payload = $row->options;
            $row->delete();

            return $payload;
        });

        if (!is_string($options) || $options === '') {
            throw new PasskeyException('挑战已过期，请重试');
        }

        return $options;
    }

    /**
     * @param  array<string, mixed>  $credential
     */
    private function loadPublicKeyCredential(array $credential): PublicKeyCredential
    {
        try {
            $loaded = $this->serializer->denormalize($credential, PublicKeyCredential::class, 'json');
        } catch (Throwable $e) {
            Log::info('Passkey credential rejected', ['reason' => $e->getMessage()]);
            throw new PasskeyException('通行钥匙登录失败');
        }
        if (!$loaded instanceof PublicKeyCredential) {
            throw new PasskeyException('通行钥匙登录失败');
        }

        return $loaded;
    }

    private function recordFromModel(WebAuthnCredential $model): CredentialRecord
    {
        $data = json_decode($model->record, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new PasskeyException('通行钥匙登录失败');
        }
        $data['counter'] = (int) $model->sign_count;
        $data['transports'] = $model->transports ?? ($data['transports'] ?? []);
        if ($model->backup_eligible !== null) {
            $data['backupEligible'] = (bool) $model->backup_eligible;
        }
        if ($model->backup_state !== null) {
            $data['backupStatus'] = (bool) $model->backup_state;
        }

        $record = $this->serializer->denormalize($data, CredentialRecord::class, 'json');
        if ($record instanceof PublicKeyCredentialSource) {
            return $record;
        }
        if (!$record instanceof CredentialRecord) {
            throw new PasskeyException('通行钥匙登录失败');
        }

        return $record;
    }

    /**
     * @param  array<int, string>  $transports
     */
    private function persistRecord(WebAuthnCredential $model, CredentialRecord $record, array $transports): void
    {
        /** @var array<string, mixed> $payload */
        $payload = $this->serializer->normalize($record, 'json');
        $payload['counter'] = $record->counter;
        $payload['transports'] = $transports !== [] ? $transports : ($record->transports ?? []);
        if ($record->backupEligible !== null) {
            $payload['backupEligible'] = $record->backupEligible;
        }
        if ($record->backupStatus !== null) {
            $payload['backupStatus'] = $record->backupStatus;
        }

        $model->record = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $model->sign_count = $record->counter;
        $model->backup_eligible = (bool) $record->backupEligible;
        $model->backup_state = (bool) $record->backupStatus;
        $model->transports = $payload['transports'];
    }

    private function findEligibleUser(string $email, bool $forAdmin): ?User
    {
        $user = User::byEmail($email)->first();
        if ($user === null || $user->banned) {
            return null;
        }
        if ($forAdmin && !$user->is_admin) {
            return null;
        }

        return $user;
    }

    private function credentialQuery(bool $forAdmin)
    {
        return WebAuthnCredential::query()->whereHas('user', function ($query) use ($forAdmin) {
            $query->where('banned', 0);
            if ($forAdmin) {
                $query->where('is_admin', 1);
            }
        });
    }

    private function purgeExpiredChallenges(): void
    {
        WebAuthnChallenge::query()->where('expires_at', '<', time())->delete();
    }

    private function rpId(): string
    {
        $rpId = strtolower(trim((string) config('webauthn.rp_id')));
        if ($rpId === '' || str_contains($rpId, '://') || str_contains($rpId, '/') || str_contains($rpId, ':')) {
            throw new PasskeyException('通行钥匙未正确配置', 500);
        }

        return $rpId;
    }

    private function rpName(): string
    {
        $name = trim((string) config('webauthn.rp_name'));

        return $name !== '' ? $name : 'XBoard';
    }

    /**
     * @return array<int, string>
     */
    private function origins(): array
    {
        $origins = config('webauthn.origins');
        if (!is_array($origins) || $origins === []) {
            throw new PasskeyException('通行钥匙未正确配置', 500);
        }

        return array_values($origins);
    }

    private function ttl(): int
    {
        $ttl = (int) config('webauthn.challenge_ttl', 300);
        if ($ttl < 60) {
            $ttl = 60;
        }
        if ($ttl > 600) {
            $ttl = 600;
        }

        return $ttl;
    }

    private function timeoutMs(): int
    {
        return $this->ttl() * 1000;
    }
}
