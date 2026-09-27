<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Tokens;

// v1 symmetric token crypto (Keystream.kt port). Confidentiality in transit
// only — the scan path rejects v1 tokens; this decodes legacy ones.
final class Keystream
{
    // WIRE-CONSTANT (do NOT rebrand)
    private const PHRASE = 'intel-verdict-token-key-v1';

    public static function decryptBytes(string $cipher): string
    {
        $key = hash('sha256', self::PHRASE, true);
        $out = $cipher;
        $block = 0;
        $off = 0;
        $len = strlen($out);
        while ($off < $len) {
            $ks = hash('sha256', $key . pack('V', $block), true);
            $take = min(32, $len - $off);
            for ($i = 0; $i < $take; $i++) {
                $out[$off + $i] = $out[$off + $i] ^ $ks[$i];
            }
            $off += 32;
            $block++;
        }
        return $out;
    }

    public static function decryptHex(string $tokenHex): string
    {
        $cipher = @hex2bin(trim($tokenHex));
        if ($cipher === false) {
            throw new \InvalidArgumentException('bad hex');
        }
        return self::decryptBytes($cipher);
    }
}
