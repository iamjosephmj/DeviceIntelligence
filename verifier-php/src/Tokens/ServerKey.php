<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Tokens;

// Loads the backend X25519 private half (ServerKey.kt port): the raw 32-byte
// scalar sodium_crypto_scalarmult consumes. Accepts PEM or raw DER PKCS#8; a
// truncated tail-32 fallback mirrors the Kotlin no-XDH path for exotic
// encodings.
final class ServerKey
{
    public static function fromBytes(string $data): string
    {
        if (str_contains($data, '-----BEGIN')) {
            return self::fromPem($data);
        }
        return self::fromPkcs8($data);
    }

    public static function fromFile(string $path): string
    {
        return self::fromBytes(file_get_contents($path));
    }

    public static function fromPem(string $pem): string
    {
        $b64 = preg_replace('/-----BEGIN [^-]*-----/', '', $pem);
        $b64 = preg_replace('/-----END [^-]*-----/', '', $b64);
        return self::fromPkcs8(base64_decode(preg_replace('/\s+/', '', $b64), true)
            ?? throw new \InvalidArgumentException('bad PEM base64'));
    }

    public static function fromPkcs8(string $der): string
    {
        if (strlen($der) < 32) {
            throw new \InvalidArgumentException("PKCS#8 X25519 key too short: " . strlen($der) . ' bytes');
        }
        return substr($der, -32); // the raw private scalar is the tail 32 bytes
    }
}
