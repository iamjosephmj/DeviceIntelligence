<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Text;

// Minimal DER TLV reader (Der.kt port) — short/long/high-tag forms, exactly
// what the KeyDescription walk needs.
final class Der
{
    /** @return array{0: array{string, string}, 1: int} [ [tag, value], nextOffset ] */
    public static function readTlv(string $b, int $i0): array
    {
        $i = $i0;
        if ($i >= strlen($b)) {
            throw new \RuntimeException('DER truncated');
        }
        $start = $i;
        $t = ord($b[$i]);
        $i++;
        if (($t & 0x1f) === 0x1f) { // high-tag-number form
            while ($i < strlen($b) && (ord($b[$i]) & 0x80) !== 0) {
                $i++;
            }
            $i++;
        }
        $tag = substr($b, $start, $i - $start);
        if ($i >= strlen($b)) {
            throw new \RuntimeException('DER truncated');
        }
        $n = ord($b[$i]);
        $i++;
        $length = $n;
        if ($n >= 0x80) {
            $k = $n & 0x7f;
            if ($k === 0 || $i + $k > strlen($b)) {
                throw new \RuntimeException('bad DER length');
            }
            $length = 0;
            for ($j = 0; $j < $k; $j++) {
                $length = ($length << 8) | ord($b[$i + $j]);
            }
            $i += $k;
        }
        if ($i + $length > strlen($b)) {
            throw new \RuntimeException('DER value out of range');
        }
        return [[$tag, substr($b, $i, $length)], $i + $length];
    }

    /** @return list<array{string, string}> */
    public static function tlvList(string $seq): array
    {
        $out = [];
        $i = 0;
        while ($i < strlen($seq)) {
            [$tlv, $i] = self::readTlv($seq, $i);
            $out[] = $tlv;
        }
        return $out;
    }

    /** @return list<array{string, string}> */
    public static function sequenceElements(string $der): array
    {
        [$outer] = self::readTlv($der, 0);
        return self::tlvList($outer[1]);
    }
}
