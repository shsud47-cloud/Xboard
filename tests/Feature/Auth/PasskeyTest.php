<?php

namespace Tests\Feature\Auth;

use App\Models\User;
use App\Models\WebAuthnChallenge;
use App\Models\WebAuthnCredential;
use App\Services\AuthService;
use App\Utils\Helper;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Support\VirtualPasskey;
use Tests\TestCase;

class PasskeyTest extends TestCase
{
    use RefreshDatabase;

    private const ORIGIN = 'http://localhost';

    private const RP_ID = 'localhost';

    protected function setUp(): void
    {
        parent::setUp();
        config()->set('app.key', 'base64:' . base64_encode(str_repeat('k', 32)));
    }

    public function test_password_login_still_works_without_a_passkey(): void
    {
        $user = $this->createUser('member@example.com', 'password-123');

        $response = $this->postJson('/api/v1/passport/auth/login', [
            'email' => $user->email,
            'password' => 'password-123',
        ]);

        $response->assertOk();
        $response->assertJsonPath('data.auth_data', fn ($token) => is_string($token) && str_starts_with($token, 'Bearer '));
        $this->assertNotEmpty($response->json('data.token'));
    }

    public function test_register_login_delete_and_cross_device_options(): void
    {
        $user = $this->createUser('member@example.com', 'password-123');
        $passkey = new VirtualPasskey();
        $auth = $this->authHeader($user);

        $this->getJson('/api/v1/passport/auth/passkey/status')
            ->assertOk()
            ->assertJsonPath('data.enabled', false);

        $options = $this->withHeaders($auth)
            ->postJson('/api/v1/user/passkey/options')
            ->assertOk()
            ->json('data');

        $this->assertSame(300000, $options['options']['timeout']);
        $this->assertSame(self::RP_ID, $options['options']['rp']['id']);
        $this->assertSame('required', $options['options']['authenticatorSelection']['residentKey']);
        $this->assertArrayNotHasKey('allowCredentials', $options['options']);

        $this->withHeaders($auth)->postJson('/api/v1/user/passkey/register', [
            'credential' => $passkey->registration($options['challenge'], self::RP_ID, 'https://evil.example'),
            'challenge' => $options['challenge'],
            'name' => 'Mac',
        ])->assertStatus(400);

        $options = $this->withHeaders($auth)->postJson('/api/v1/user/passkey/options')->assertOk()->json('data');
        $this->withHeaders($auth)->postJson('/api/v1/user/passkey/register', [
            'credential' => $passkey->registration($options['challenge'], self::RP_ID, self::ORIGIN),
            'challenge' => $options['challenge'],
            'name' => 'Mac',
            'transports' => ['internal'],
        ])->assertOk()->assertJsonPath('data.name', 'Mac');

        $this->postJson('/api/v1/passport/auth/login', [
            'email' => $user->email,
            'password' => 'password-123',
        ])->assertOk()->assertJsonPath('data.is_admin', false);

        $this->getJson('/api/v1/passport/auth/passkey/status?email=' . urlencode($user->email))
            ->assertOk()
            ->assertJsonPath('data.available', true);
        $this->getJson('/api/v1/passport/auth/passkey/status?email=other@example.com')
            ->assertOk()
            ->assertJsonPath('data.available', false);

        $loginOptions = $this->postJson('/api/v1/passport/auth/passkey/options', [])
            ->assertOk()
            ->json('data');
        $this->assertSame(300000, $loginOptions['options']['timeout']);
        $this->assertSame(self::RP_ID, $loginOptions['options']['rpId']);
        $this->assertSame('preferred', $loginOptions['options']['userVerification']);
        $this->assertArrayNotHasKey('allowCredentials', $loginOptions['options']);

        $named = $this->postJson('/api/v1/passport/auth/passkey/options', ['email' => $user->email])
            ->assertOk()
            ->json('data.options');
        $this->assertArrayHasKey('allowCredentials', $named);
        $this->assertContains('hybrid', $named['allowCredentials'][0]['transports']);
        $this->assertContains('internal', $named['allowCredentials'][0]['transports']);

        $userHandle = $options['options']['user']['id'];
        $assertion = $passkey->assertion($loginOptions['challenge'], self::RP_ID, self::ORIGIN, $userHandle);
        $login = $this->postJson('/api/v1/passport/auth/passkey/login', [
            'credential' => $assertion,
            'challenge' => $loginOptions['challenge'],
        ])->assertOk();
        $this->assertStringStartsWith('Bearer ', $login->json('data.auth_data'));

        $this->postJson('/api/v1/passport/auth/passkey/login', [
            'credential' => $assertion,
            'challenge' => $loginOptions['challenge'],
        ])->assertStatus(400)->assertJsonPath('message', '挑战已过期，请重试');

        $again = $this->postJson('/api/v1/passport/auth/passkey/options', ['email' => $user->email])->assertOk()->json('data');
        $this->postJson('/api/v2/passport/auth/passkey/login', [
            'credential' => $passkey->assertion($again['challenge'], self::RP_ID, self::ORIGIN, $userHandle),
            'challenge' => $again['challenge'],
            'email' => $user->email,
        ])->assertOk();

        $this->withHeaders($auth)->getJson('/api/v1/user/passkey')
            ->assertOk()
            ->assertJsonPath('data.credentials.0.name', 'Mac')
            ->assertJsonCount(1, 'data.credentials');

        $id = WebAuthnCredential::query()->first()->id;
        $this->withHeaders($auth)->postJson('/api/v1/user/passkey/delete', ['id' => $id])->assertOk();
        $this->assertSame(0, WebAuthnCredential::query()->count());

        $this->postJson('/api/v1/passport/auth/login', [
            'email' => $user->email,
            'password' => 'password-123',
        ])->assertOk();
    }

    public function test_admin_passkey_rejects_members_and_accepts_admins(): void
    {
        $member = $this->createUser('member@example.com', 'password-123');
        $admin = $this->createUser('admin@example.com', 'password-123', true);
        $passkey = new VirtualPasskey();
        $auth = $this->authHeader($admin);

        $options = $this->withHeaders($auth)->postJson('/api/v2/user/passkey/options')->assertOk()->json('data');
        $this->withHeaders($auth)->postJson('/api/v2/user/passkey/register', [
            'credential' => $passkey->registration($options['challenge'], self::RP_ID, self::ORIGIN),
            'challenge' => $options['challenge'],
            'name' => 'Windows',
        ])->assertOk();

        $memberOptions = $this->postJson('/api/v1/passport/auth/passkey/options', [
            'email' => $member->email,
            'for_admin' => true,
        ]);
        $memberOptions->assertStatus(400)->assertJsonPath('message', '用户不存在或未注册通行钥匙');

        $loginOptions = $this->postJson('/api/v1/passport/auth/passkey/options', [
            'email' => $admin->email,
            'for_admin' => true,
        ])->assertOk()->json('data');

        $this->postJson('/api/v1/passport/auth/passkey/login', [
            'credential' => $passkey->assertion(
                $loginOptions['challenge'],
                self::RP_ID,
                self::ORIGIN,
                $options['options']['user']['id']
            ),
            'challenge' => $loginOptions['challenge'],
            'email' => $admin->email,
            'for_admin' => true,
        ])->assertOk()->assertJsonPath('data.is_admin', true);

        $this->getJson('/api/v1/passport/auth/passkey/status?for_admin=1')
            ->assertOk()
            ->assertJsonPath('data.enabled', true);
    }

    public function test_expired_challenge_is_rejected(): void
    {
        $user = $this->createUser('member@example.com', 'password-123');
        $auth = $this->authHeader($user);
        $options = $this->withHeaders($auth)->postJson('/api/v1/user/passkey/options')->assertOk()->json('data');
        WebAuthnChallenge::query()->where('challenge', $options['challenge'])->update(['expires_at' => time() - 10]);

        $passkey = new VirtualPasskey();
        $this->withHeaders($auth)->postJson('/api/v1/user/passkey/register', [
            'credential' => $passkey->registration($options['challenge'], self::RP_ID, self::ORIGIN),
            'challenge' => $options['challenge'],
            'name' => 'Mac',
        ])->assertStatus(400)->assertJsonPath('message', '挑战已过期，请重试');
    }

    public function test_banned_user_cannot_sign_in_with_a_passkey(): void
    {
        $user = $this->createUser('member@example.com', 'password-123');
        $passkey = new VirtualPasskey();
        $auth = $this->authHeader($user);
        $options = $this->withHeaders($auth)->postJson('/api/v1/user/passkey/options')->assertOk()->json('data');
        $this->withHeaders($auth)->postJson('/api/v1/user/passkey/register', [
            'credential' => $passkey->registration($options['challenge'], self::RP_ID, self::ORIGIN),
            'challenge' => $options['challenge'],
            'name' => 'Mac',
        ])->assertOk();

        $user->banned = true;
        $user->save();

        $this->postJson('/api/v1/passport/auth/passkey/options', ['email' => $user->email])
            ->assertStatus(400)
            ->assertJsonPath('message', '用户不存在或未注册通行钥匙');

        $user->delete();
        $this->assertSame(0, WebAuthnCredential::query()->count());
    }

    public function test_register_requires_an_existing_session(): void
    {
        $this->postJson('/api/v1/user/passkey/options')->assertStatus(403);
    }

    private function createUser(string $email, string $password, bool $admin = false): User
    {
        return User::query()->create([
            'email' => $email,
            'password' => password_hash($password, PASSWORD_DEFAULT),
            'uuid' => Helper::guid(true),
            'token' => Helper::guid(),
            'is_admin' => $admin,
            'created_at' => time(),
            'updated_at' => time(),
        ]);
    }

    private function authHeader(User $user): array
    {
        $data = (new AuthService($user))->generateAuthData();

        return ['Authorization' => $data['auth_data']];
    }
}
