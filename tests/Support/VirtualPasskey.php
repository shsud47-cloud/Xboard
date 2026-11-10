<?php

namespace Tests\Support;

use CBOR\ByteStringObject;
use CBOR\Encoder;
use CBOR\MapObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Paragonie\ConstantTime\Base64UrlSafe;

/**
 * Minimal ES256 authenticator that speaks the same JSON the browser sends.
 */
final class VirtualPasskey
{
    public string $credentialId;

    private string $x;

    private string $y;

    private string $d;

    public int $signCount = 0;

    public function __construct()
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $details = openssl_pkey_get_details($key);
        $this->x = str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT);
        $this->y = str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);
        $this->d = str_pad($details['ec']['d'], 32, "\0", STR_PAD_LEFT);
        $this->credentialId = random_bytes(16);
    }

    public function registration(string $challenge, string $rpId, string $origin): array
    {
        $clientData = $this->clientData('webauthn.create', $challenge, $origin);
        $authData = $this->authData($rpId, true);
        $encoder = new Encoder();
        $attestation = $encoder->encode([
            'fmt' => 'none',
            'attStmt' => MapObject::create(),
            'authData' => ByteStringObject::create($authData),
        ]);

        return $this->credentialJson($clientData, [
            'attestationObject' => Base64UrlSafe::encodeUnpadded($attestation),
        ]);
    }

    public function assertion(string $challenge, string $rpId, string $origin, ?string $userHandle): array
    {
        $clientData = $this->clientData('webauthn.get', $challenge, $origin);
        $authData = $this->authData($rpId, false);
        $key = new Ec2Key([
            Key::TYPE => Key::TYPE_EC2,
            Key::ALG => -7,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => $this->x,
            Ec2Key::DATA_Y => $this->y,
            Ec2Key::DATA_D => $this->d,
        ]);
        $signature = ES256::create()->sign($authData . hash('sha256', $clientData, true), $key);
        $response = [
            'authenticatorData' => Base64UrlSafe::encodeUnpadded($authData),
            'signature' => Base64UrlSafe::encodeUnpadded($signature),
        ];
        if ($userHandle !== null && $userHandle !== '') {
            $response['userHandle'] = $userHandle;
        }

        return $this->credentialJson($clientData, $response);
    }

    private function clientData(string $type, string $challenge, string $origin): string
    {
        return json_encode([
            'type' => $type,
            'challenge' => $challenge,
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_UNESCAPED_SLASHES);
    }

    private function authData(string $rpId, bool $attested): string
    {
        $flags = $attested ? 0x45 : 0x05;
        $data = hash('sha256', $rpId, true) . chr($flags) . pack('N', $this->signCount);
        if (!$attested) {
            return $data;
        }

        $cose = (new Encoder())->encode([
            1 => 2,
            3 => -7,
            -1 => 1,
            -2 => ByteStringObject::create($this->x),
            -3 => ByteStringObject::create($this->y),
        ]);

        return $data
            . str_repeat("\0", 16)
            . pack('n', strlen($this->credentialId))
            . $this->credentialId
            . $cose;
    }

    private function credentialJson(string $clientData, array $response): array
    {
        $rawId = Base64UrlSafe::encodeUnpadded($this->credentialId);

        return [
            'id' => $rawId,
            'rawId' => $rawId,
            'type' => 'public-key',
            'response' => ['clientDataJSON' => Base64UrlSafe::encodeUnpadded($clientData)] + $response,
        ];
    }
}
