<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Attestation;

// HKDF-SHA256 (RFC 5869) on the stdlib hash_hkdf.
final class Hkdf
{
    public const MAX_OUT = 255 * 32;

    public static function sha256(string $ikm, string $salt, string $info, int $length): string
    {
        if ($length < 0 || $length > self::MAX_OUT) {
            throw new \RangeException("HKDF outLen out of range: {$length}");
        }
        $salt = $salt === '' ? str_repeat("\x00", 32) : $salt; // RFC convention
        return hash_hkdf('sha256', $ikm, $length, $info, $salt);
    }
}
