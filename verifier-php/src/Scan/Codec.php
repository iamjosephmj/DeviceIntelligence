<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Scan;

// JSON round-trip for ScanSession (ScanSessionCodec.kt port). Decode grades a
// truncated document DOWN to the suspicious value, never to the benign default
// — a missing boolean always reads as the dangerous one.
final class Codec
{
    public static function decode(string $jsonText): array
    {
        $o = json_decode($jsonText, true, flags: JSON_THROW_ON_ERROR);
        $key = $o['attestedKey'] ?? null;
        if (!is_string($key)) {
            throw new \InvalidArgumentException('session has no attestedKey');
        }
        $app = $o['attestedApp'] ?? null;
        $fp = $o['fingerprint'] ?? null;
        return [
            'attestedKey' => $key,
            'attestedApp' => is_array($app) ? [
                'packageNames' => $app['packageNames'] ?? [],
                'signatureDigests' => $app['signatureDigests'] ?? [],
            ] : null,
            'assurance' => is_string($o['assurance'] ?? null) ? $o['assurance'] : 'SOFTWARE',
            'bootState' => $o['bootState'] ?? '?',
            'deviceLocked' => ($o['deviceLocked'] ?? null) === true,
            'chainTrusted' => ($o['chainTrusted'] ?? null) === true,
            'keyboxRevoked' => ($o['keyboxRevoked'] ?? null) !== false,
            'crossLevelReuse' => ($o['crossLevelReuse'] ?? null) !== false,
            'devicePropMismatch' => ($o['devicePropMismatch'] ?? null) !== false,
            'bootStateSpoofer' => ($o['bootStateSpoofer'] ?? null) !== false,
            'strongboxChainMissing' => ($o['strongboxChainMissing'] ?? null) !== false,
            'softwareAttested' => ($o['softwareAttested'] ?? null) !== false,
            'osPatchLevel' => $o['osPatchLevel'] ?? null,
            'vendorPatchLevel' => $o['vendorPatchLevel'] ?? null,
            'bootPatchLevel' => $o['bootPatchLevel'] ?? null,
            'fingerprint' => is_array($fp) ? [
                'id' => $fp['id'] ?? null,
                'aid' => $fp['aid'] ?? null,
                'securityLevel' => $fp['securityLevel'] ?? null,
                'build' => $fp['build'] ?? null,
                'kernel' => $fp['kernel'] ?? null,
                'patch' => $fp['patch'] ?? null,
                'installer' => $fp['installer'] ?? null,
            ] : null,
        ];
    }

    public static function encode(array $s): string
    {
        $f = ['"attestedKey":' . json_encode($s['attestedKey'], JSON_THROW_ON_ERROR)];
        if ($s['attestedApp'] === null) {
            $f[] = '"attestedApp":null';
        } else {
            $f[] = '"attestedApp":{"packageNames":' . json_encode($s['attestedApp']['packageNames'], JSON_THROW_ON_ERROR)
                . ',"signatureDigests":' . json_encode($s['attestedApp']['signatureDigests'], JSON_THROW_ON_ERROR) . '}';
        }
        $f[] = '"assurance":' . json_encode($s['assurance']);
        $f[] = '"bootState":' . json_encode($s['bootState']);
        $f[] = '"deviceLocked":' . self::bool($s['deviceLocked']);
        $f[] = '"chainTrusted":' . self::bool($s['chainTrusted']);
        $f[] = '"keyboxRevoked":' . self::bool($s['keyboxRevoked']);
        $f[] = '"crossLevelReuse":' . self::bool($s['crossLevelReuse']);
        $f[] = '"devicePropMismatch":' . self::bool($s['devicePropMismatch']);
        $f[] = '"bootStateSpoofer":' . self::bool($s['bootStateSpoofer']);
        $f[] = '"strongboxChainMissing":' . self::bool($s['strongboxChainMissing']);
        $f[] = '"softwareAttested":' . self::bool($s['softwareAttested']);
        $f[] = '"osPatchLevel":' . self::intOrNull($s['osPatchLevel']);
        $f[] = '"vendorPatchLevel":' . self::intOrNull($s['vendorPatchLevel']);
        $f[] = '"bootPatchLevel":' . self::intOrNull($s['bootPatchLevel']);
        if ($s['fingerprint'] === null) {
            $f[] = '"fingerprint":null';
        } else {
            $pairs = [];
            foreach (['id', 'aid', 'securityLevel', 'build', 'kernel', 'patch', 'installer'] as $k) {
                $v = $s['fingerprint'][$k] ?? null;
                $pairs[] = json_encode($k, JSON_THROW_ON_ERROR) . ':' . ($v === null ? 'null' : json_encode($v, JSON_THROW_ON_ERROR));
            }
            $f[] = '"fingerprint":{' . implode(',', $pairs) . '}';
        }
        return '{' . implode(',', $f) . '}';
    }

    private static function bool(bool $v): string
    {
        return $v ? 'true' : 'false';
    }

    private static function intOrNull(?int $v): string
    {
        return $v === null ? 'null' : (string) $v;
    }
}
