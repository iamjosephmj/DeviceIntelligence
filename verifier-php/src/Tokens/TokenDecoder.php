<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Tokens;

use DeviceIntelligenceVerifier\Policy\Policy;
use DeviceIntelligenceVerifier\Policy\Registry;

// Decrypts a token and returns its document WITHOUT verifying
// (TokenDecoder.kt port).
final class TokenDecoder
{
    public const BINDING_SEP = "\n--BINDING\n";

    public function __construct(
        private readonly Registry $registry,
        private readonly Policy $policy,
    ) {
    }

    public function decode(string $tokenHex): array
    {
        $text = Keystream::decryptHex($tokenHex);
        $idx = strpos($text, self::BINDING_SEP);
        $signed = $idx === false ? $text : substr($text, 0, $idx);
        $doc = json_decode($signed, true, flags: JSON_THROW_ON_ERROR);
        return [
            'schemaVersion' => $doc['schemaVersion'] ?? null,
            'point' => $doc['point'] ?? null,
            'ts' => $doc['ts'] ?? null,
            'nonce' => $doc['nonce'] ?? null,
            'device' => Signals::device($doc),
            'signals' => Signals::resolve($doc, $this->registry, $this->policy),
            'hasBinding' => $idx !== false,
        ];
    }
}
