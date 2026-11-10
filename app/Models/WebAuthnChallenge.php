<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class WebAuthnChallenge extends Model
{
    public const CEREMONY_REGISTER = 'register';

    public const CEREMONY_LOGIN = 'login';

    public $timestamps = false;

    protected $table = 'v2_webauthn_challenges';

    protected $guarded = ['id'];

    protected $casts = [
        'user_id' => 'integer',
        'expires_at' => 'integer',
        'created_at' => 'integer',
    ];
}
