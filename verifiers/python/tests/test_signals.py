import json
from deviceintelligence_verifier.policy import Policy
from deviceintelligence_verifier.registry import SignalRegistry
from deviceintelligence_verifier.signals import resolve
from deviceintelligence_verifier.models import definitive_hooks

REG = SignalRegistry.bundled()
POL = Policy()


def test_resolves_enrichment_attributes():
    doc = json.loads('{"signals":[{"id":"INTEL_0044","severity":"HIGH","detail":"Injected '
                     'native library. path=/data/adb/modules/evilmod/zygisk/arm64-v8a.so '
                     'module_id=evilmod needed=liblog.so,libc.so links_hook_lib=libdobby.so"}]}')
    sig = resolve(doc, REG, POL)[0]
    assert sig.module_id == "evilmod"
    assert sig.linked_libraries == ["liblog.so", "libc.so"]
    assert sig.links_hook_lib == "libdobby.so"
    assert sig.path == "/data/adb/modules/evilmod/zygisk/arm64-v8a.so"


def test_resolves_got_hijack_symbol_attributes():
    doc = json.loads('{"signals":[{"id":"INTEL_0031","severity":"CRITICAL","detail":"hooked '
                     'function pointer. lib=/system/lib64/libbinder.so hooked_symbol=ioctl '
                     'hooked_by=evilmod"}]}')
    sig = resolve(doc, REG, POL)[0]
    assert sig.hooked_symbol == "ioctl" and sig.hooked_by == "evilmod"


def test_correlates_definitive_hook_structural_plus_behavioral():
    doc = json.loads('{"signals":[{"id":"INTEL_0003","severity":"CRITICAL","detail":"inline '
                     'hook. hooked_symbol=faccessat hooked_by=evilmod"},{"id":"INTEL_0059",'
                     '"severity":"HIGH","detail":"lie. hooked_symbol=faccessat '
                     'path=/system/bin/sh"},{"id":"INTEL_0003","severity":"CRITICAL",'
                     '"detail":"inline hook. hooked_symbol=openat hooked_by=evilmod"}]}')
    assert definitive_hooks(resolve(doc, REG, POL)) == ["faccessat"]


def test_unknown_signal_falls_back_to_question_marks():
    doc = json.loads('{"signals":[{"id":"INTEL_9999","severity":"CRITICAL"}]}')
    sig = resolve(doc, REG, POL)[0]
    assert sig.detector == "?" and sig.kind == "?" and sig.severity == "CRITICAL"


def test_legacy_sig_prefix_bridges_to_intel():
    doc = json.loads('{"signals":[{"id":"SIG_0052","severity":"CRITICAL"}]}')
    assert resolve(doc, REG, POL)[0].id == "INTEL_0052"
