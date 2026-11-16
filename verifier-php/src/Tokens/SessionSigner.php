<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Tokens;

// Stateless HMAC-signed session tokens (SessionSigner.kt port). The token is
// "<payload-b64url>.<mac-b64url>"; tampering with either half fails.
final class SessionSigner
{
    public const DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60;

    public function __construct(
        private readonly string $key,
        private readonly int $maxAgeSeconds = self::DEFAULT_MAX_AGE_SECONDS,
        private readonly ?\Closure $now = null,
    ) {
    }

    private function now(): int
    {
        return $this->now !== null ? ($this->now)() : time();
    }

    public function issue(array $session): string
    {
        $payload = json_encode([
            'pinnedKey' => $session['pinnedKeySpkiHex'],
            'assurance' => $session['assurance'],
            'boot' => $session['bootState'],
            'locked' => $session['deviceLocked'],
            'issuedAt' => $session['issuedAt'],
            'chainTrusted' => $session['chainTrusted'],
            'kbRevoked' => $session['keyboxRevoked'],
            'xlReuse' => $session['crossLevelReuse'],
            'sbMissing' => $session['strongboxChainMissing'],
            'propMismatch' => $session['devicePropMismatch'],
            'bootSpoofer' => $session['bootStateSpoofer'],
            'swAttest' => $session['softwareAttested'],
        ], JSON_THROW_ON_ERROR);
        return $this->b64url($payload) . '.' . $this->b64url($this->mac($payload));
    }

    /** The carried session facts, or null on tamper / wrong key / expiry / malformed. */
    public function open(string $sessionId): ?array
    {
        $dot = strpos($sessionId, '.');
        if ($dot === false) {
            return null;
        }
        $payload = $this->unb64url(substr($sessionId, 0, $dot));
        $mac = $this->unb64url(substr($sessionId, $dot + 1));
        if ($payload === null || $mac === null) {
            return null;
        }
        if (!hash_equals($this->mac($payload), $mac)) {
            return null;
        }
        try {
            $o = json_decode($payload, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        $issuedAt = $o['issuedAt'] ?? null;
        if (!is_int($issuedAt) || $issuedAt <= 0 || $this->now() - $issuedAt > $this->maxAgeSeconds) {
            return null;
        }
        return [
            'pinnedKeySpkiHex' => $o['pinnedKey'] ?? '',
            'assurance' => $o['assurance'] ?? '',
            'bootState' => $o['boot'] ?? '',
            'deviceLocked' => ($o['locked'] ?? null) === true,
            'issuedAt' => $issuedAt,
            'chainTrusted' => ($o['chainTrusted'] ?? null) === true,
            'keyboxRevoked' => ($o['kbRevoked'] ?? null) === true,
            'crossLevelReuse' => ($o['xlReuse'] ?? null) === true,
            'strongboxChainMissing' => ($o['sbMissing'] ?? null) === true,
            'devicePropMismatch' => ($o['propMismatch'] ?? null) === true,
            'bootStateSpoofer' => ($o['bootSpoofer'] ?? null) === true,
            'softwareAttested' => ($o['swAttest'] ?? null) === true,
        ];
    }

    private function mac(string $data): string
    {
        return hash_hmac('sha256', $data, $this->key, true);
    }

    private function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private function unb64url(string $s): ?string
    {
        $padded = strtr($s, '-_', '+/');
        $padded .= str_repeat('=', (4 - strlen($padded) % 4) % 4);
        $out = base64_decode($padded, true);
        return $out === false ? null : $out;
    }
}
