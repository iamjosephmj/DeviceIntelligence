<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier;

// Attestation-key revocation list (the weekly-baked encrypted crl.bin asset,
// already decrypted by the caller). Serial matching normalizes case, an
// optional 0x prefix, and leading zeros away — "0" stays "0".
final class AttestationCrl
{
    private function __construct(private array $revoked)
    {
    }

    public static function normalize(string $serialHex): string
    {
        $s = strtoupper(trim($serialHex));
        if (str_starts_with($s, '0X')) {
            $s = substr($s, 2);
        }
        $s = ltrim($s, '0');
        return $s === '' ? '0' : $s;
    }

    public static function parse(string $text): self
    {
        $revoked = [];
        foreach (explode("\n", $text) as $line) {
            $n = self::normalize(explode('#', $line)[0]);
            if ($n !== '') {
                $revoked[$n] = true;
            }
        }
        return new self($revoked);
    }

    public static function fromFile(string $path): self
    {
        return self::parse(file_get_contents($path));
    }

    public function revoked(string $serialHex): bool
    {
        return isset($this->revoked[self::normalize($serialHex)]);
    }

    public function size(): int
    {
        return count($this->revoked);
    }
}
