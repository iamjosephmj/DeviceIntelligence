<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Attestation;

use DeviceIntelligenceVerifier\Text\Der;

// Android Key Attestation extension reader (Attestation.kt port), on the
// minimal DER walker. KeyDescription element indexes (spec §8): [1]
// attestationSecurityLevel, [4] attestationChallenge, [6] softwareEnforced,
// [7] teeEnforced — [7] preferred. RootOfTrust entry tag: BF 85 40.
final class Attestation
{
    public const OID_HEX = '2b06010401d679020111'; // 1.3.6.1.4.1.11129.2.1.17
    private const ROOT_OF_TRUST_TAG = "\xBF\x85\x40";

    public const SECURITY_LEVEL_NAMES = [0 => 'Software', 1 => 'TrustedEnvironment', 2 => 'StrongBox'];
    public const BOOT_STATE_NAMES = [0 => 'Verified', 1 => 'SelfSigned', 2 => 'Unverified', 3 => 'Failed'];

    /** @return array{security_level: ?int, verified_boot_state: ?int, device_locked: ?bool} */
    public static function fields(string $leafDer): array
    {
        $elems = Der::sequenceElements(self::keyDescriptionDer($leafDer));
        $securityLevel = count($elems) > 1 && $elems[1][1] !== '' ? ord($elems[1][1][0]) : null;

        $locked = null;
        $bootState = null;
        // teeEnforced [7] preferred over softwareEnforced [6]; both are plain
        // SEQUENCEs whose entries carry the context tags.
        foreach ([7, 6] as $idx) {
            if (count($elems) <= $idx || $bootState !== null) {
                continue;
            }
            foreach (Der::tlvList($elems[$idx][1]) as $entry) {
                if ($entry[0] !== self::ROOT_OF_TRUST_TAG) {
                    continue;
                }
                $rot = Der::tlvList($entry[1]);
                if (count($rot) > 1 && $rot[1][1] !== '') {
                    $locked = ord($rot[1][1][0]) !== 0;
                }
                if (count($rot) > 2 && $rot[2][1] !== '') {
                    $bootState = ord($rot[2][1][0]);
                }
                break;
            }
        }
        return ['security_level' => $securityLevel, 'verified_boot_state' => $bootState, 'device_locked' => $locked];
    }

    public static function challenge(string $leafDer): string
    {
        $elems = Der::sequenceElements(self::keyDescriptionDer($leafDer));
        if (count($elems) <= 4) {
            throw new \RuntimeException('KeyDescription too short');
        }
        return $elems[4][1];
    }

    public static function securityLevelName(?int $level): string
    {
        return $level === null ? '?' : (self::SECURITY_LEVEL_NAMES[$level] ?? (string) $level);
    }

    public static function bootStateName(?int $state): string
    {
        return $state === null ? '?' : (self::BOOT_STATE_NAMES[$state] ?? (string) $state);
    }

    // The KeyDescription DER: walk Certificate > tbsCertificate > [3]
    // extensions, find our OID, return the extnValue OCTET STRING content.
    public static function keyDescriptionDer(string $leafDer): string
    {
        $oidBytes = @hex2bin(self::OID_HEX);
        if ($oidBytes === false) {
            throw new \RuntimeException('bad OID');
        }
        // Certificate element [0] is tbsCertificate; the [3] extensions tag
        // lives among ITS elements, one level deeper.
        $certElems = Der::sequenceElements($leafDer);
        if ($certElems === []) {
            throw new \RuntimeException('empty certificate DER');
        }
        // Element [0] of Certificate IS the tbsCertificate SEQUENCE — do not
        // descend into it; iterate its elements for the [3] extensions tag.
        $tbs = $certElems[0];
        $tbsElems = Der::tlvList($tbs[1]);
        foreach ($tbsElems as $e) {
                if ($e[0][0] !== "\xA3") { // [3] extensions, explicit
                continue;
            }
            $extSeq = Der::readTlv($e[1], 0)[0];
            $exts = Der::tlvList($extSeq[1]);
                foreach ($exts as $ext) {
                $parts = Der::tlvList($ext[1]);
                        if (count($parts) >= 2 && $parts[0][1] === $oidBytes) {
                    return $parts[count($parts) - 1][1]; // extnValue content
                }
            }
        }
        throw new \RuntimeException('no Android attestation extension on leaf');
    }
}
