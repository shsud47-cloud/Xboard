<?php

namespace App\Http\Controllers\V1\User;

use App\Http\Controllers\Controller;
use App\Services\Auth\WebAuthn\PasskeyException;
use App\Services\Auth\WebAuthn\WebAuthnService;
use Illuminate\Http\Request;

class PasskeyController extends Controller
{
    public function __construct(private WebAuthnService $webAuthn)
    {
    }

    public function index(Request $request)
    {
        return $this->success([
            'credentials' => $this->webAuthn->list($request->user()),
        ]);
    }

    public function options(Request $request)
    {
        return $this->guard(fn () => $this->success($this->webAuthn->registerOptions($request->user())));
    }

    public function register(Request $request)
    {
        $data = $request->validate([
            'credential' => 'required|array',
            'challenge' => 'required|string|max:200',
            'name' => 'nullable|string|max:64',
            'transports' => 'nullable|array|max:8',
            'transports.*' => 'string|max:32',
        ]);

        return $this->guard(function () use ($request, $data) {
            $credential = $this->webAuthn->register(
                $request->user(),
                $data['credential'],
                $data['challenge'],
                (string) ($data['name'] ?? ''),
                $data['transports'] ?? []
            );

            return $this->success([
                'id' => $credential->id,
                'name' => $credential->name,
            ]);
        });
    }

    public function delete(Request $request)
    {
        $data = $request->validate([
            'id' => 'required|integer|min:1',
        ]);

        return $this->guard(function () use ($request, $data) {
            $this->webAuthn->delete($request->user(), (int) $data['id']);

            return $this->success(true);
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
