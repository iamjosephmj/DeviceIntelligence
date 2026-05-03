// CTF Flag 1 payload class.
//
// Compiled and converted to DEX by build-payload.sh. The DEX bytes
// are loaded into the running sample app via either
// InMemoryDexClassLoader (channel-b harness) or DexClassLoader
// from /data/local/tmp/ (channel-a harness). The class itself is
// trivial; what matters is that ART has to register a brand-new
// DexFile in the running process to load it, which is exactly the
// runtime tampering signal the DexInjection helper inside
// runtime.environment watches for.
public class Payload {
    public static String hello() {
        return "DeviceIntelligence CTF Flag 1 — runtime DEX injection";
    }
}
