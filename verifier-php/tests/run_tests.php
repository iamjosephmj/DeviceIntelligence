<?php

declare(strict_types=1);

// The PHP verifier suite: the same vectors the python/node/kotlin suites pin,
// run by a self-contained checker (no phpunit dependency — `php tests/run_tests.php`).

require __DIR__ . '/../src/Der.php';
require __DIR__ . '/../src/Keystream.php';
require __DIR__ . '/../src/Hkdf.php';
require __DIR__ . '/../src/LabKeys.php';
require __DIR__ . '/../src/Registry.php';
require __DIR__ . '/../src/Policy.php';
require __DIR__ . '/../src/Signals.php';
require __DIR__ . '/../src/X25519.php';
require __DIR__ . '/../src/TokenCryptoV2.php';
require __DIR__ . '/../src/SessionSigner.php';
require __DIR__ . '/../src/ServerKey.php';
require __DIR__ . '/../src/PinnedRoots.php';
require __DIR__ . '/../src/ChainVerifier.php';
require __DIR__ . '/../src/AttestationCrl.php';
require __DIR__ . '/../src/Attestation.php';
require __DIR__ . '/../src/TokenDecoder.php';
require __DIR__ . '/../src/TokenVerifier.php';
require __DIR__ . '/../src/Codec.php';

use DeviceIntelligenceVerifier\AttestationCrl;
use DeviceIntelligenceVerifier\Codec;
use DeviceIntelligenceVerifier\Hkdf;
use DeviceIntelligenceVerifier\Keystream;
use DeviceIntelligenceVerifier\LabKeys;
use DeviceIntelligenceVerifier\Policy;
use DeviceIntelligenceVerifier\Registry;
use DeviceIntelligenceVerifier\ServerKey;
use DeviceIntelligenceVerifier\SessionSigner;
use DeviceIntelligenceVerifier\Signals;
use DeviceIntelligenceVerifier\TokenCryptoV2;
use DeviceIntelligenceVerifier\TokenDecoder;
use DeviceIntelligenceVerifier\TokenVerifier;
use DeviceIntelligenceVerifier\X25519;

define('ISSUED_AT', 1_787_220_000);

$FAILS = 0;
$RUNS = 0;

function check(bool $cond, string $label): void
{
    global $FAILS, $RUNS;
    $RUNS++;
    if (!$cond) {
        $FAILS++;
        echo "FAIL: $label\n";
    }
}

function throws(callable $fn): bool
{
    try {
        $fn();
        return false;
    } catch (\Throwable) {
        return true;
    }
}

$FIXTURES = __DIR__ . '/../../verifiers/fixtures';

// ---- HKDF (RFC 5869) ------------------------------------------------------
$ikm22 = str_repeat("\x0b", 22);
check(bin2hex(Hkdf::sha256($ikm22, hex2bin('000102030405060708090a0b0c'),
    hex2bin('f0f1f2f3f4f5f6f7f8f9'), 42)) ===
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf' .
    '34007208d5b887185865', 'hkdf rfc5869 case1');
check(bin2hex(Hkdf::sha256($ikm22, '', '', 42)) ===
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d' .
    '9d201395faa4b61a96c8', 'hkdf rfc5869 case3');
check(throws(fn () => Hkdf::sha256("\x01", '', '', 255 * 32 + 1)), 'hkdf rejects over 255 blocks');
check(strlen(Hkdf::sha256(str_repeat("\x00", 32), str_repeat("\x10", 12), "intel-token-v2\x00", 32)) === 32,
    'hkdf token derivation shape');

// ---- Policy ---------------------------------------------------------------
$p = new Policy();
check($p->isBlocking('INTEL_0001', 'CRITICAL'), 'policy critical blocks');
check(!$p->isBlocking('INTEL_0019', 'HIGH'), 'policy high does not block');
check(!$p->isBlocking('INTEL_0050', 'MEDIUM'), 'policy medium does not block');
check(!(new Policy(allow: ['INTEL_0052']))->isBlocking('INTEL_0052', 'CRITICAL'), 'policy allow overrides');
check((new Policy(block: ['INTEL_0050']))->isBlocking('INTEL_0050', 'MEDIUM'), 'policy block overrides');
$ab = new Policy(allow: ['INTEL_0001'], block: ['INTEL_0001']);
check(!$ab->isBlocking('INTEL_0001', 'CRITICAL'), 'policy allow over block');
check($p->isBlocking(null, 'critical'), 'policy severity case-insensitive');
check(!$p->isBlocking(null, null), 'policy null severity');
check((new Policy(observeUnconfirmedRwx: true))->isBlocking(
    'INTEL_0052', 'CRITICAL', 'rwx_memory_mapping', 3), 'policy confirmed rwx blocks');
check($p->isBlocking('INTEL_0052', 'CRITICAL', 'rwx_memory_mapping', 0),
    'policy bare rwx blocks by default');
check(!(new Policy(observeUnconfirmedRwx: true))->isBlocking(
    'INTEL_0052', 'CRITICAL', 'rwx_memory_mapping', 0), 'policy bare rwx downgrades when opted in');

// ---- Registry -------------------------------------------------------------
$reg = Registry::bundled();
check($reg->size() === 61, 'registry size 61');
$m42 = $reg->get('INTEL_0042');
check($m42 !== null && $m42['detector'] === 'native_integrity'
    && $m42['kind'] === 'text_integrity_divergence'
    && $m42['severity'] === 'CRITICAL', 'registry INTEL_0042');
check($reg->get('INTEL_0020') === null && $reg->get('INTEL_0039') === null, 'registry retired absent');
$row9999 = Registry::fromJson('{"signals":[{"id":"INTEL_9999"}]}')->get('INTEL_9999');
check($row9999 !== null && $row9999['detector'] === '?' && $row9999['kind'] === '?', 'registry unknown ??');
check($reg->get(null) === null, 'registry null-safe');

// ---- Signals --------------------------------------------------------------
$doc = json_decode('{"signals":[{"id":"INTEL_0044","severity":"HIGH","detail":"Injected ' .
    'native library. path=/data/adb/modules/evilmod/zygisk/arm64-v8a.so ' .
    'module_id=evilmod needed=liblog.so,libc.so links_hook_lib=libdobby.so"}]}', true);
$sig = Signals::resolve($doc, $reg, $p)[0];
check($sig['attributes']['module_id'] === 'evilmod'
    && $sig['attributes']['needed'] === 'liblog.so,libc.so'
    && $sig['attributes']['links_hook_lib'] === 'libdobby.so'
    && $sig['attributes']['path'] === '/data/adb/modules/evilmod/zygisk/arm64-v8a.so',
    'signals enrichment attrs');

$doc = json_decode('{"signals":[{"id":"INTEL_0031","severity":"CRITICAL","detail":"hooked ' .
    'function pointer. lib=/system/lib64/libbinder.so hooked_symbol=ioctl hooked_by=evilmod"}]}', true);
$sig = Signals::resolve($doc, $reg, $p)[0];
check($sig['attributes']['hooked_symbol'] === 'ioctl'
    && $sig['attributes']['hooked_by'] === 'evilmod', 'signals got hijack attrs');

$doc = json_decode('{"signals":[{"id":"INTEL_0003","severity":"CRITICAL","detail":"inline ' .
    'hook. hooked_symbol=faccessat hooked_by=evilmod"},{"id":"INTEL_0059",' .
    '"severity":"HIGH","detail":"lie. hooked_symbol=faccessat path=/system/bin/sh"},' .
    '{"id":"INTEL_0003","severity":"CRITICAL","detail":"inline hook. hooked_symbol=openat hooked_by=evilmod"}]}', true);
check(Signals::definitiveHooks(Signals::resolve($doc, $reg, $p)) === ['faccessat'],
    'signals definitive hooks correlate');

$doc = json_decode('{"signals":[{"id":"INTEL_9999","severity":"CRITICAL"}]}', true);
$sig = Signals::resolve($doc, $reg, $p)[0];
check($sig['detector'] === '?' && $sig['kind'] === '?' && $sig['severity'] === 'CRITICAL',
    'signals unknown fallback');

$doc = json_decode('{"signals":[{"id":"SIG_0052","severity":"CRITICAL"}]}', true);
check(Signals::resolve($doc, $reg, $p)[0]['id'] === 'INTEL_0052', 'signals SIG_ bridge');

// ---- X25519 (RFC 7748, via sodium — the v2 envelope primitive) ------------
$x = fn (string $k, string $u) => bin2hex(sodium_crypto_scalarmult(hex2bin($k), hex2bin($u)));
check($x('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
    'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c') ===
    'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552', 'x25519 rfc7748 v1');
check($x('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
    'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493') ===
    '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957', 'x25519 rfc7748 v2');

// ---- v2 ECIES (native-interop KAT + tamper matrix) ------------------------
$SERVER = hex2bin('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
$TOKEN = '2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d10111213' .
    '1415161718191a1bf5fea180751d9d9068b0634b833499c54b955d2f849d9a3520574a600d852a' .
    '2ff5909230650def8d9ce6fbe5c5f191285ba2c66e12a44b';
$EMPTY = '2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d1011' .
    '12131415161718191a1b9a7f7296f43354e241400ee7b8946c46';
$EXPECTED = "signed_content\n--BINDING\nSIG...\nCERT...";

check(TokenCryptoV2::decrypt($TOKEN, $SERVER) === $EXPECTED, 'v2 decrypts native token');
check(TokenCryptoV2::decrypt($EMPTY, $SERVER) === '', 'v2 decrypts empty ciphertext');

$flip = fn (string $t, int $i) => '2:' . substr($t, 2, $i) .
    (substr($t, 2 + $i, 1) === '0' ? '1' : '0') . substr($t, 3 + $i);
foreach ([0, 2, 10, 70, 92] as $i) {
    check(throws(fn () => TokenCryptoV2::decrypt($flip($TOKEN, $i), $SERVER)),
        "v2 tamper at $i fails");
}
check(throws(fn () => TokenCryptoV2::decrypt($flip($TOKEN, strlen($TOKEN) - 3), $SERVER)),
    'v2 tamper tag fails');
$other = '02' . substr('0202030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21', 2);
check(throws(fn () => TokenCryptoV2::decrypt($TOKEN, hex2bin($other))), 'v2 wrong key fails');
$zeroBody = '2:' . substr($TOKEN, 2, 4) . str_repeat('0', 64) . substr($TOKEN, 68);
check(throws(fn () => TokenCryptoV2::decrypt($zeroBody, $SERVER)), 'v2 all-zero eph fails');
check(throws(fn () => TokenCryptoV2::decrypt('deadbeefcafe', $SERVER)), 'v2 rejects missing prefix');
check(throws(fn () => TokenCryptoV2::decrypt('2:0203', $SERVER)), 'v2 rejects too short');
check(throws(fn () => TokenCryptoV2::decrypt('2:abc', $SERVER)), 'v2 rejects odd hex');
check(throws(fn () => TokenCryptoV2::decrypt('2:zzzz', $SERVER)), 'v2 rejects non hex');
check(TokenCryptoV2::isV2($TOKEN) && !TokenCryptoV2::isV2('deadbeefcafe')
    && !TokenCryptoV2::isV2('') && !TokenCryptoV2::isV2('2'), 'is v2 discriminates');

// ---- Session signer -------------------------------------------------------
$signer = new SessionSigner(LabKeys::SERVER_KEY, now: fn () => ISSUED_AT + 100);
$SESSION = [
    'pinnedKeySpkiHex' => '30591301deadbeef', 'assurance' => 'STRONGBOX',
    'bootState' => 'Verified', 'deviceLocked' => true, 'issuedAt' => 1_787_220_000,
    'chainTrusted' => false, 'keyboxRevoked' => false, 'crossLevelReuse' => false,
    'strongboxChainMissing' => false, 'devicePropMismatch' => false,
    'bootStateSpoofer' => false, 'softwareAttested' => false,
];
check(signer_round_trips($SESSION, ISSUED_AT), 'signer round trips');
$late = new SessionSigner(LabKeys::SERVER_KEY, now: fn () => ISSUED_AT + SessionSigner::DEFAULT_MAX_AGE_SECONDS + 1);
check($late->open($signer->issue($SESSION)) === null, 'signer rejects expired');
$stampless = $SESSION;
$stampless['issuedAt'] = 0;
$zero = new SessionSigner(LabKeys::SERVER_KEY, now: fn () => 0);
check($signer->open($zero->issue($stampless)) === null, 'signer rejects zero timestamp');
[$payload, $mac] = explode('.', $signer->issue($SESSION), 2);
$forged = substr($payload, 0, -1) . (str_ends_with($payload, 'A') ? 'B' : 'A') . '.' . $mac;
check($signer->open($forged) === null, 'signer rejects tampered payload');
$forgedSigner = new SessionSigner('different-key', now: fn () => ISSUED_AT + 100);
check($forgedSigner->open($signer->issue($SESSION)) === null, 'signer rejects wrong key');
check($signer->open('not-a-session') === null, 'signer rejects malformed');

function signer_round_trips(array $session, int $at): bool
{
    $signer = new SessionSigner(LabKeys::SERVER_KEY, now: fn () => $at + 100);
    return $signer->open($signer->issue($session)) === $session;
}

// ---- Codec ----------------------------------------------------------------
$codec = Codec::class;
$full = [
    'attestedKey' => '3059301306072a8648ce3d020106082a8648ce3d03010703420004aabb',
    'attestedApp' => ['packageNames' => ['com.example.app', 'com.example.other'],
        'signatureDigests' => [str_repeat('aa', 32), str_repeat('bb', 32)]],
    'assurance' => 'STRONGBOX', 'bootState' => 'Verified', 'deviceLocked' => true,
    'chainTrusted' => true, 'keyboxRevoked' => false, 'crossLevelReuse' => false,
    'devicePropMismatch' => false, 'bootStateSpoofer' => false,
    'strongboxChainMissing' => false, 'softwareAttested' => false,
    'osPatchLevel' => 202604, 'vendorPatchLevel' => 20260405, 'bootPatchLevel' => 20260405,
    'fingerprint' => ['id' => str_repeat('cc', 32), 'aid' => str_repeat('dd', 32),
        'securityLevel' => 'L1', 'build' => 'google/raven/raven:16/BP41.250:user/release-keys',
        'kernel' => '6.1.145-android14-11', 'patch' => '2026-04-05',
        'installer' => 'com.android.vending'],
];
check(Codec::decode(Codec::encode($full)) === $full, 'codec full session round trips');
check(throws(fn () => Codec::decode('{"assurance":"TEE"}')), 'codec rejects malformed');

// ---- Token decoder + pixel parity ----------------------------------------
$nonce = trim(file_get_contents("$FIXTURES/pixel-nonce.hex"));
$decoder = new TokenDecoder(Registry::bundled(), new Policy());
$decoded = $decoder->decode(trim(file_get_contents("$FIXTURES/pixel-challenge.token")));
check($decoded['schemaVersion'] === 3 && $decoded['hasBinding'], 'decoder challenge fixture');

$res = (new TokenVerifier())->verify(
    trim(file_get_contents("$FIXTURES/pixel-token.hex")),
    trim(file_get_contents("$FIXTURES/pixel-nonce.hex")));
check($res['authentic'] === true, 'pixel parity: authentic');
check($res['deviceIntegrityOk'] === false, 'pixel parity: device integrity fails');
check($res['decision'] === 'COMPROMISED', 'pixel parity: COMPROMISED');
$sig0 = null;
foreach ($res['signals'] as $s) {
    if ($s['id'] === 'INTEL_0000') {
        $sig0 = $s;
    }
}
check($sig0 !== null && $sig0['blocking'], 'pixel parity: INTEL_0000 blocking');
$byName = [];
foreach ($res['checks'] as $c) {
    $byName[$c['name']] = $c['ok'];
}
check($byName['binding present'] === true, 'pixel parity: binding present');
check($byName['nonce matches issued'] === true, 'pixel parity: nonce');
check($byName['chain -> pinned Google root'] === true, 'pixel parity: pinned root');
check($byName['signature over verdict'] === true, 'pixel parity: signature');
check(($byName['verified boot state = Verified'] ?? true) === false,
    'pixel parity: boot state must fail');

echo $FAILS === 0
    ? "ALL {$RUNS} CHECKS PASSED\n"
    : "{$FAILS} of {$RUNS} checks FAILED\n";
exit($FAILS === 0 ? 0 : 1);
