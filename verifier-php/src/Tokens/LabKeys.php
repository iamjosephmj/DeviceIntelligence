<?php

declare(strict_types=1);

namespace DeviceIntelligenceVerifier\Tokens;

// Fixed lab HMAC key for stateless session tokens — shared by every port.
final class LabKeys
{
    public const SERVER_KEY = 'intel-lab-session-key-v1';
}
