<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Tokens;

use DeviceIntelligenceVerifier\Attestation\Hkdf;

// v2 ECIES token crypto (TokenCryptoV2.kt port) + the v1 discriminator.
// Wire: "2:" + hex(version || epoch || eph_pub(32) || nonce(12) || ct || tag).
// Every corruption fails the GCM tag — a tampered token never decrypts.
final class TokenCryptoV2
{
    public const PREFIX = '2:';
    private const INFO_PREFIX = 'intel-token-v2';
    private const HEADER = 1 + 1 + 32 + 12;
    private const TAG = 16;

    public static function isV2(string $token): bool
    {
        return str_starts_with($token, self::PREFIX);
    }

    /** [serverPriv] is the raw 32-byte X25519 private scalar. */
    public static function decrypt(string $tokenV2, string $serverScalar): string
    {
        if (strlen($serverScalar) !== 32) {
            throw new \InvalidArgumentException('server private scalar must be 32 bytes');
        }
        if (!str_starts_with($tokenV2, self::PREFIX)) {
            throw new \InvalidArgumentException('not a v2 token');
        }
        $body = substr($tokenV2, strlen(self::PREFIX));
        if (strlen($body) % 2 !== 0) {
            throw new \InvalidArgumentException('odd-length hex');
        }
        if (!ctype_xdigit($body)) {
            throw new \InvalidArgumentException('bad hex char');
        }
        $p = @hex2bin($body);
        if ($p === false || strlen($p) < self::HEADER + self::TAG) {
            throw new \InvalidArgumentException('v2 token too short');
        }

        $version = $p[0];
        $epoch = $p[1];
        $ephPub = substr($p, 2, 32);
        $nonce = substr($p, 34, 12);
        $ctAndTag = substr($p, self::HEADER);

        $eph = $ephPub;
        $eph[31] = $eph[31] & "\x7F"; // RFC 7748: the ignored high bit
        $shared = sodium_crypto_scalarmult($serverScalar, $eph);
        $key = Hkdf::sha256($shared, $nonce, self::INFO_PREFIX . $epoch, 32);

        $aad = $version . $epoch . $ephPub;
        $ct = substr($ctAndTag, 0, strlen($ctAndTag) - self::TAG);
        $tag = substr($ctAndTag, strlen($ctAndTag) - self::TAG);

        $plain = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
        if ($plain === false) {
            throw new \RuntimeException('gcm auth failed');
        }
        return $plain;
    }
}
