<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier;

// The signal taxonomy: opaque INTEL_ codes resolved to their meaning. The
// device never ships detector/kind — only the backend holds the table.
final class Registry
{
    /** @param array<string, array{detector: string, kind: string, severity: string, title: string}> $byID */
    private function __construct(private array $byID)
    {
    }

    public static function fromJson(string $text): self
    {
        $root = json_decode($text, true, flags: JSON_THROW_ON_ERROR);
        $byID = [];
        foreach ($root['signals'] ?? [] as $row) {
            if (($row['status'] ?? '') === 'retired') {
                continue;
            }
            $byID[$row['id']] = [
                'detector' => $row['detector'] ?? '?',
                'kind' => $row['kind'] ?? '?',
                'severity' => $row['severity'] ?? '',
                'title' => $row['title'] ?? '',
            ];
        }
        return new self($byID);
    }

    public static function bundled(): self
    {
        $path = __DIR__ . '/resources/signals-registry.json';
        return self::fromJson(file_get_contents($path));
    }

    /** Nil-safe: unknown codes, null — null back. @return array|null */
    public function get(?string $id): ?array
    {
        return $id !== null ? ($this->byID[$id] ?? null) : null;
    }

    public function size(): int
    {
        return count($this->byID);
    }
}
