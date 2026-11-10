<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class WebAuthnCredential extends Model
{
    protected $table = 'v2_webauthn_credentials';

    protected $dateFormat = 'U';

    protected $guarded = ['id'];

    protected $casts = [
        'created_at' => 'timestamp',
        'updated_at' => 'timestamp',
        'sign_count' => 'integer',
        'backup_eligible' => 'boolean',
        'backup_state' => 'boolean',
        'last_used_at' => 'integer',
        'transports' => 'array',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id', 'id');
    }
}
