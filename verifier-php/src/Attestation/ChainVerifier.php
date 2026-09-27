<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Attestation;

// Token attestation chain validation (ChainVerifier.kt port). Signature-only:
// each cert signed by the next, and the chain top must terminate in a pinned
// Google root (by SHA-256 of the DER, or by key verification — Pixel chains
// mix EC keyboxes with RSA Google intermediates).
final class ChainVerifier
{
    /** @return list<array{pem: string, der: string, fp: string}> leaf first. */
    public static function parseChain(array $certsHex): array
    {
        $chain = [];
        foreach ($certsHex as $h) {
            $der = @hex2bin($h);
            if ($der === false) {
                throw new \RuntimeException('bad cert hex');
            }
            $chain[] = [
                'pem' => PinnedRoots::toPem($der),
                'der' => $der,
                'fp' => hash('sha256', $der),
            ];
        }
        return $chain;
    }

    /** Returns the pinned root (fp => der) the chain terminates in. */
    public static function verifyToPinnedRoot(array $chain, array $pinnedRoots): array
    {
        if ($chain === []) {
            throw new \RuntimeException('empty chain');
        }
        for ($i = 0; $i + 1 < count($chain); $i++) {
            self::verifySignedBy($chain[$i]['pem'], $chain[$i + 1]['pem']);
        }
        $top = $chain[count($chain) - 1];
        foreach ($pinnedRoots as $root) {
            if ($top['fp'] === $root['fp']) {
                return $root;
            }
            if (self::verifySignedBy($top['pem'], $root['pem'])) {
                return $root;
            }
        }
        throw new \RuntimeException('chain top does not chain to a pinned Google root');
    }

    /** True iff [certPem] is signed by [issuerPem]'s key. */
    public static function verifySignedBy(string $certPem, string $issuerPem): bool
    {
        $cert = openssl_x509_read($certPem);
        $key = openssl_pkey_get_public($issuerPem);
        if ($cert === false || $key === false) {
            return false;
        }
        return openssl_x509_verify($cert, $key) === 1;
    }
}
