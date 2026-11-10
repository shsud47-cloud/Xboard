<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        if (!Schema::hasTable('v2_webauthn_credentials')) {
            Schema::create('v2_webauthn_credentials', function (Blueprint $table) {
                $table->increments('id');
                $table->unsignedInteger('user_id')->index();
                // Base64url credential id. 512 chars stays within MySQL's utf8mb4 unique index limit.
                $table->string('credential_id', 512)->unique();
                $table->longText('record');
                $table->unsignedInteger('sign_count')->default(0);
                $table->text('transports')->nullable();
                $table->string('name', 64);
                $table->string('aaguid', 36)->nullable();
                $table->boolean('backup_eligible')->default(false);
                $table->boolean('backup_state')->default(false);
                $table->unsignedInteger('last_used_at')->nullable();
                $table->unsignedInteger('created_at');
                $table->unsignedInteger('updated_at');
            });
        }

        if (!Schema::hasTable('v2_webauthn_challenges')) {
            Schema::create('v2_webauthn_challenges', function (Blueprint $table) {
                $table->increments('id');
                $table->string('challenge', 128)->unique();
                $table->unsignedInteger('user_id')->nullable()->index();
                $table->string('ceremony', 16);
                $table->longText('options');
                $table->unsignedInteger('expires_at')->index();
                $table->unsignedInteger('created_at');
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('v2_webauthn_challenges');
        Schema::dropIfExists('v2_webauthn_credentials');
    }
};
