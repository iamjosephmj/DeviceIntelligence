<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier;

// X25519 — the v2 envelope's key agreement, on ext-sodium's
// sodium_crypto_scalarmult (RFC 7748; libsodium applies the standard clamping
// and rejects trivial (all-zero) outputs, which is what the tamper matrix
// asserts).
final class X25519
{
    /** Both arguments are raw 32-byte little-endian values. */
    public static function sharedSecret(string $scalar, string $u): string
    {
        if (strlen($scalar) !== 32 || strlen($u) !== 32) {
            throw new \InvalidArgumentException('X25519 operands must be 32 bytes');
        }
        return sodium_crypto_scalarmult($scalar, $u);
    }
}
