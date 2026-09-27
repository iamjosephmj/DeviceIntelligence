<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier;

// Signal resolution: turn the device's opaque findings into registry-backed
// resolved signals, and correlate structural + behavioral hook evidence.
final class Signals
{
    // The detail tokens a backend may enrich with (space-separated k=v pairs).
    private const ATTR_KEYS = [
        'path', 'module_id', 'needed', 'links_hook_lib', 'hooked_symbol',
        'hooked_by', 'target', 'ondisk_confirmed', 'on_disk_prologue',
        'trampoline_class', 'object', 'base', 'seals', 'key', 'get', 'area',
        'hook_stub_regions', 'region_count',
    ];

    public static function parseAttrs(string $detail): array
    {
        $attrs = [];
        if ($detail === '') {
            return $attrs;
        }
        foreach (explode(' ', $detail) as $tok) {
            $eq = strpos($tok, '=');
            if ($eq === false || $eq === 0) {
                continue;
            }
            $k = substr($tok, 0, $eq);
            if (in_array($k, self::ATTR_KEYS, true)) {
                $attrs[$k] = substr($tok, $eq + 1);
            }
        }
        return $attrs;
    }

    public static function resolve(array $doc, Registry $registry, Policy $policy): array
    {
        $out = [];
        foreach ($doc['signals'] ?? [] as $s) {
            $rawID = $s['id'] ?? 'INTEL_UNKNOWN';
            // Legacy SIG_-prefixed ids normalize before lookup.
            $id = str_starts_with($rawID, 'SIG_') ? 'INTEL_' . substr($rawID, 4) : $rawID;
            $meta = $registry->get($id);
            $severity = $s['severity'] ?? ($meta['severity'] ?? '');
            $detail = $s['detail'] ?? '';
            $attrs = self::parseAttrs($detail);
            $stubs = isset($attrs['hook_stub_regions']) ? (int) $attrs['hook_stub_regions'] : 0;
            $out[] = [
                'id' => $id,
                'detector' => $meta['detector'] ?? '?',
                'kind' => $meta['kind'] ?? '?',
                'title' => $meta['title'] ?? '',
                'severity' => $severity,
                'detail' => $detail,
                'blocking' => $policy->isBlocking(
                    $id,
                    $severity,
                    $meta['kind'] ?? null,
                    $stubs,
                ),
                'attributes' => $attrs,
            ];
        }
        return $out;
    }

    public static function device(array $doc): ?array
    {
        $d = $doc['device'] ?? null;
        if (!is_array($d)) {
            return null;
        }
        return [
            'api' => is_int($d['api'] ?? null) ? $d['api'] : null,
            'abi' => $d['abi'] ?? null,
            'model' => $d['model'] ?? null,
        ];
    }

    // Definitive hook = the SAME symbol seen both structurally (inline hook /
    // stub) and behaviorally (syscall divergence). Sorted for determinism.
    public static function definitiveHooks(array $signals): array
    {
        $structural = [];
        $behavioral = [];
        foreach ($signals as $s) {
            $sym = $s['attributes']['hooked_symbol'] ?? null;
            if ($sym === null) {
                continue;
            }
            if ($s['kind'] === 'libc_inline_hook' || $s['kind'] === 'libc_inline_stub') {
                $structural[$sym] = true;
            } elseif ($s['kind'] === 'syscall_divergence') {
                $behavioral[$sym] = true;
            }
        }
        $both = array_intersect(array_keys($structural), array_keys($behavioral));
        sort($both);
        return array_values($both);
    }
}
