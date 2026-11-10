<?php

namespace App\Http\Controllers\V1\Passport;

use App\Http\Controllers\Controller;
use App\Services\Auth\WebAuthn\PasskeyException;
use App\Services\Auth\WebAuthn\WebAuthnService;
use App\Services\AuthService;
use Illuminate\Http\Request;

class PasskeyController extends Controller
{
    public function __construct(private WebAuthnService $webAuthn)
    {
    }

    public function status(Request $request)
    {
        $email = $request->input('email', $request->query('email'));

        return $this->success($this->webAuthn->status(
            is_string($email) ? trim($email) : null,
            $request->boolean('for_admin')
        ));
    }

    public function options(Request $request)
    {
        $data = $request->validate([
            'email' => 'nullable|string|max:255',
            'for_admin' => 'nullable|boolean',
        ]);

        return $this->guard(function () use ($data, $request) {
            $email = isset($data['email']) ? trim((string) $data['email']) : null;

            return $this->success($this->webAuthn->loginOptions($email, $request->boolean('for_admin')));
        });
    }

    public function login(Request $request)
    {
        $data = $request->validate([
            'credential' => 'required|array',
            'challenge' => 'required|string|max:200',
            'email' => 'nullable|string|max:255',
            'for_admin' => 'nullable|boolean',
        ]);

        return $this->guard(function () use ($data, $request) {
            $email = isset($data['email']) ? trim((string) $data['email']) : null;
            $user = $this->webAuthn->login(
                $data['credential'],
                $data['challenge'],
                $email,
                $request->boolean('for_admin')
            );
            $authService = new AuthService($user);

            return $this->success($authService->generateAuthData());
        });
    }

    private function guard(callable $callback)
    {
        try {
            return $callback();
        } catch (PasskeyException $e) {
            return $this->fail([$e->status, $e->getMessage()]);
        }
    }
}
