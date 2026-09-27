<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier;

// The pinned Google hardware-attestation roots (PinnedRoots.kt port).
// Bundled file: base64 DER, one root per line, '#' comments allowed.
final class PinnedRoots
{
    /** @return list<array{pem: string, fp: string}> pem + sha256 fingerprint (hex) */
    public static function parse(string $text): array
    {
        $roots = [];
        foreach (explode("\n", $text) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $der = base64_decode($line, true);
            if ($der === false) {
                throw new \RuntimeException('bad base64 pinned root');
            }
            $roots[] = ['pem' => self::toPem($der), 'fp' => hash('sha256', $der), 'der' => $der];
        }
        return $roots;
    }

    public static function default(): array
    {
        return self::parse(file_get_contents(__DIR__ . '/resources/pinned-roots.txt'));
    }

    public static function toPem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" .
            chunk_split(base64_encode($der), 64, "\n") .
            "-----END CERTIFICATE-----\n";
    }
}
