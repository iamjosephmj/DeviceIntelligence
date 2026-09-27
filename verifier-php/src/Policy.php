<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier;

// Server-side policy — the false-positive tuning that lives OFF the device.
final class Policy
{
    public function __construct(
        public readonly array $blockSeverities = ['CRITICAL'],
        public readonly array $allow = [],
        public readonly array $block = [],
        public readonly bool $requireStrongBox = false,
        public readonly int $maxPatchAgeDays = 365,
        public readonly bool $observeUnconfirmedRwx = false,
    ) {
    }

    // The single blocking decision. Order is normative:
    //   1. allow-list wins over everything
    //   2. block-list wins over severity
    //   3. a CONFIRMED RWX hook pool always blocks
    //   4. opting into observe-unconfirmed-RWX downgrades a BARE RWX finding
    //   5. otherwise the severity table decides
    public function isBlocking(
        ?string $id = null,
        ?string $severity = null,
        ?string $kind = null,
        ?int $hookStubRegions = null,
    ): bool {
        if ($id !== null && in_array($id, $this->allow, true)) {
            return false;
        }
        if ($id !== null && in_array($id, $this->block, true)) {
            return true;
        }
        if ($kind === 'rwx_memory_mapping') {
            if (($hookStubRegions ?? 0) > 0) {
                return true;
            }
            if ($this->observeUnconfirmedRwx) {
                return false;
            }
        }
        return in_array(strtoupper($severity ?? ''), $this->blockSeverities, true);
    }
}
