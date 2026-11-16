"""DeviceIntelligence licence generator. Mints the RVN2 `server.key` asset
(X25519 public half + signed licence: package hash, expiry, epoch) and the
backend private PEM — byte-identical to LicenceKeygen.generate() and to what
dicore's licence_blob.cpp validates.

The bundled publisher key is the DEV key compiled into the SDK (public by
assumption): the blob check is a fail-fast, not a security control. Release
builds must mint key material through the release pipeline instead."""
from .keys import PUBLISHER_KEY, LicenceMaterial, build_blob, generate_licence

__all__ = ["PUBLISHER_KEY", "LicenceMaterial", "build_blob", "generate_licence"]
