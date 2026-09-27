<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Tokens;

use DeviceIntelligenceVerifier\Attestation\Attestation;
use DeviceIntelligenceVerifier\Attestation\ChainVerifier;
use DeviceIntelligenceVerifier\Attestation\PinnedRoots;
use DeviceIntelligenceVerifier\Policy\Policy;
use DeviceIntelligenceVerifier\Policy\Registry;

// The v1-era verify flow (TokenVerifier.kt port): authenticity + TEE facts.
// Layered like every port: AUTH failures => REJECT, INTEGRITY failures =>
// COMPROMISED, blocking signals => COMPROMISED, else TRUSTWORTHY.
final class TokenVerifier
{
    public const BINDING_SEP = "\n--BINDING\n";
    public const FS = "\x1F";

    public function __construct(
        ?Registry $registry = null,
        ?Policy $policy = null,
        ?array $pinnedRoots = null,
    ) {
        $this->registry = $registry ?? Registry::bundled();
        $this->policy = $policy ?? new Policy();
        $this->pinnedRoots = $pinnedRoots ?? PinnedRoots::default();
    }

    public static function bundled(): self
    {
        return new self(Registry::bundled(), new Policy(), PinnedRoots::default());
    }

    /** @return array the VerificationResult (assoc, same keys as every port). */
    public function verify(string $tokenHex, string $issuedNonce): array
    {
        $checks = new Checks();

        $text = Keystream::decryptHex($tokenHex);
        $sep = strpos($text, self::BINDING_SEP);
        $hasBinding = $sep !== false;
        $signed = $hasBinding ? substr($text, 0, $sep) : $text;
        $binding = $hasBinding ? substr($text, $sep + strlen(self::BINDING_SEP)) : '';
        $doc = json_decode($signed, true);
        if (!is_array($doc)) {
            $doc = [];
        }

        if (!$checks->auth('binding present', $hasBinding,
            $hasBinding ? '' : 'unbound/legacy token')) {
            return $this->result($checks, $doc);
        }
        if ($doc === []) {
            $checks->auth('signed content is JSON', false, 'unparseable signed_content');
            return $this->result($checks, $doc);
        }

        $tokenNonce = $doc['nonce'] ?? '';
        $checks->auth('nonce matches issued', $tokenNonce === $issuedNonce);

        [$sigHex, $certsHex] = self::parseBinding($binding);
        if (!$checks->auth('chain + signature present',
            $sigHex !== '' && $certsHex !== [])) {
            return $this->result($checks, $doc);
        }

        try {
            $chain = ChainVerifier::parseChain($certsHex);
        } catch (\RuntimeException) {
            $chain = [];
        }
        if (!$checks->auth('chain parses', $chain !== [],
            $chain === [] ? 'could not parse cert chain' : '')) {
            return $this->result($checks, $doc);
        }
        $leaf = $chain[0];

        try {
            $root = ChainVerifier::verifyToPinnedRoot($chain, $this->pinnedRoots);
            $checks->auth('chain -> pinned Google root', true, $root['fp']);
        } catch (\RuntimeException $e) {
            $checks->auth('chain -> pinned Google root', false, $e->getMessage());
        }

        $chal = null;
        try {
            $chal = Attestation::challenge($leaf['der']);
        } catch (\RuntimeException) {
        }
        $checks->auth('attestation challenge == nonce',
            $chal !== null && bin2hex($chal) === strtolower($issuedNonce));

        $sigOk = false;
        try {
            $cert = openssl_x509_read($leaf['pem']);
            $pub = openssl_pkey_get_public($cert);
            $sigOk = openssl_verify($signed, hex2bin($sigHex), $pub, OPENSSL_ALGO_SHA256) === 1;
        } catch (\Exception) {
            $sigOk = false;
        }
        $checks->auth('signature over verdict', $sigOk, $sigOk ? '' : 'ECDSA verify failed');

        // Device-integrity layer — the TEE's own attestation fields.
        $fields = null;
        try {
            $fields = Attestation::fields($leaf['der']);
        } catch (\RuntimeException) {
        }
        $sec = $fields !== null && in_array($fields['security_level'], [1, 2], true);
        $checks->integ('hardware security level >= TEE', $sec,
            $fields !== null ? Attestation::securityLevelName($fields['security_level']) : 'parse error');
        $boot = $fields !== null && $fields['verified_boot_state'] === 0;
        $checks->integ('verified boot state = Verified', $boot,
            $fields !== null ? Attestation::bootStateName($fields['verified_boot_state']) : 'parse error');
        $locked = $fields !== null && $fields['device_locked'] === true;
        $checks->integ('device locked', $locked,
            $fields !== null ? var_export($fields['device_locked'], true) : 'parse error');

        return $this->result($checks, $doc);
    }

    /** The layered verdict: REJECT unless authentic; COMPROMISED on any integrity
     *  failure or blocking signal; TRUSTWORTHY only when all three layers clear. */
    private function result(Checks $checks, array $doc): array
    {
        $authentic = $checks->authentic();
        $deviceOk = $checks->deviceIntegrityOk();
        $signals = Signals::resolve($doc, $this->registry, $this->policy);
        $blocking = false;
        foreach ($signals as $s) {
            if ($s['blocking']) {
                $blocking = true;
                break;
            }
        }
        $decision = !$authentic ? 'REJECT'
            : (!$deviceOk || $blocking ? 'COMPROMISED' : 'TRUSTWORTHY');
        return [
            'decision' => $decision,
            'authentic' => $authentic,
            'deviceIntegrityOk' => $deviceOk,
            'checks' => $checks->toList(),
            'schemaVersion' => $doc['schemaVersion'] ?? null,
            'point' => $doc['point'] ?? null,
            'ts' => $doc['ts'] ?? null,
            'nonce' => $doc['nonce'] ?? null,
            'device' => Signals::device($doc),
            'signals' => $signals,
        ];
    }

    /** SIG<US>hex and the CERT<US>hex lines out of the binding payload. */
    private static function parseBinding(string $binding): array
    {
        $sigHex = '';
        $certsHex = [];
        foreach (explode("\n", $binding) as $line) {
            if (str_starts_with($line, 'SIG' . self::FS)) {
                $sigHex = substr($line, 4);
            } elseif (str_starts_with($line, 'CERT' . self::FS)) {
                $certsHex[] = substr($line, 5);
            }
        }
        return [$sigHex, $certsHex];
    }
}

// The check ledger: gates record under their layer; the two layer verdicts
// fall out of the ledger.
final class Checks
{
    private array $all = [];

    public function auth(string $name, bool $ok, string $detail = ''): bool
    {
        $this->all[] = ['name' => $name, 'ok' => $ok, 'detail' => $detail, 'kind' => 'AUTH'];
        return $ok;
    }

    public function integ(string $name, bool $ok, string $detail = ''): bool
    {
        $this->all[] = ['name' => $name, 'ok' => $ok, 'detail' => $detail, 'kind' => 'INTEGRITY'];
        return $ok;
    }

    public function authentic(): bool
    {
        foreach ($this->all as $c) {
            if ($c['kind'] === 'AUTH' && !$c['ok']) {
                return false;
            }
        }
        return true;
    }

    public function deviceIntegrityOk(): bool
    {
        foreach ($this->all as $c) {
            if ($c['kind'] === 'INTEGRITY' && !$c['ok']) {
                return false;
            }
        }
        return true;
    }

    /** @return list<array{name: string, ok: bool, detail: string, kind: string}> */
    public function toList(): array
    {
        return $this->all;
    }
}
