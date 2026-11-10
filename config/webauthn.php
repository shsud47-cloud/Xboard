<?php

$originList = env('WEBAUTHN_ORIGINS', env('WEBAUTHN_ORIGIN', 'https://xboard.finn47.xyz'));

return [
    /*
    | Relying Party ID is the site hostname. A passkey created for this host
    | cannot be used on any other host. Production target: xboard.finn47.xyz.
    */
    'rp_id' => env('WEBAUTHN_RP_ID', 'xboard.finn47.xyz'),

    'rp_name' => env('WEBAUTHN_RP_NAME', env('APP_NAME', 'XBoard')),

    /*
    | Full origins allowed in clientDataJSON. Comma-separated.
    | Production target: https://xboard.finn47.xyz
    */
    'origins' => array_values(array_filter(array_map(
        static fn ($origin) => trim((string) $origin),
        explode(',', (string) $originList)
    ))),

    // Seconds. Dee Panel uses 5 minutes; the browser timeout is this value in ms.
    'challenge_ttl' => (int) env('WEBAUTHN_CHALLENGE_TTL', 300),
];
