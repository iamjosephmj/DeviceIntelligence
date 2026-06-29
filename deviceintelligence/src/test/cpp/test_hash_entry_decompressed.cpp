// Host test for dicore::zip::hash_entry_decompressed.
// Compile: see step 2. Run on x86_64 Android emulator via ADB.
#include "dicore/zip_parser.h"
#include "dicore/apkmap.h"
#include "dicore/sha256.h"
#include "dicore/hex.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include <zlib.h>

using namespace dicore;

// ---- Minimal ZIP writer -----------------------------------------------
static void w16(std::vector<uint8_t>& v, uint16_t x) { v.push_back(x&0xFF); v.push_back(x>>8); }
static void w32(std::vector<uint8_t>& v, uint32_t x) { for(int i=0;i<4;i++){v.push_back(x&0xFF);x>>=8;} }

struct CdEntry { std::string name; uint32_t lfh_off, comp_sz, uncomp_sz, crc32v; uint16_t method; };

static uint32_t crc32_buf(const uint8_t* p, size_t n) {
    return (uint32_t)::crc32(::crc32(0L, Z_NULL, 0), p, (uInt)n);
}

static void emit_lfh(std::vector<uint8_t>& v, CdEntry& e) {
    e.lfh_off = (uint32_t)v.size();
    w32(v,0x04034b50u); w16(v,20); w16(v,0); w16(v,e.method);
    w16(v,0); w16(v,0);
    w32(v,e.crc32v); w32(v,e.comp_sz); w32(v,e.uncomp_sz);
    w16(v,(uint16_t)e.name.size()); w16(v,0);
    for(char c:e.name) v.push_back((uint8_t)c);
}

static std::vector<uint8_t> build_zip(
    const char* stored_name, const uint8_t* stored_data, uint32_t stored_len,
    const char* deflated_name, const uint8_t* plain, uint32_t plain_len)
{
    std::vector<uint8_t> zip;
    std::vector<CdEntry> entries;

    // STORED entry
    {
        CdEntry e; e.name=stored_name; e.method=0;
        e.uncomp_sz=stored_len; e.comp_sz=stored_len;
        e.crc32v=crc32_buf(stored_data,stored_len);
        emit_lfh(zip,e);
        for(uint32_t i=0;i<stored_len;i++) zip.push_back(stored_data[i]);
        entries.push_back(e);
    }

    // DEFLATED entry — raw deflate (no zlib header)
    {
        std::vector<uint8_t> comp(compressBound(plain_len));
        z_stream zs{}; deflateInit2(&zs,Z_DEFAULT_COMPRESSION,Z_DEFLATED,-MAX_WBITS,8,Z_DEFAULT_STRATEGY);
        zs.next_in=const_cast<Bytef*>(plain); zs.avail_in=plain_len;
        zs.next_out=comp.data(); zs.avail_out=(uInt)comp.size();
        deflate(&zs,Z_FINISH); uint32_t csz=(uint32_t)zs.total_out; deflateEnd(&zs);

        CdEntry e; e.name=deflated_name; e.method=8;
        e.uncomp_sz=plain_len; e.comp_sz=csz;
        e.crc32v=crc32_buf(plain,plain_len);
        emit_lfh(zip,e);
        for(uint32_t i=0;i<csz;i++) zip.push_back(comp[i]);
        entries.push_back(e);
    }

    // Central directory
    uint32_t cd_start=(uint32_t)zip.size();
    for(auto& e:entries){
        w32(zip,0x02014b50u); w16(zip,20); w16(zip,20); w16(zip,0); w16(zip,e.method);
        w16(zip,0); w16(zip,0);
        w32(zip,e.crc32v); w32(zip,e.comp_sz); w32(zip,e.uncomp_sz);
        w16(zip,(uint16_t)e.name.size()); w16(zip,0); w16(zip,0);
        w16(zip,0); w16(zip,0); w32(zip,0); w32(zip,e.lfh_off);
        for(char c:e.name) zip.push_back((uint8_t)c);
    }
    uint32_t cd_sz=(uint32_t)zip.size()-cd_start;
    w32(zip,0x06054b50u); w16(zip,0); w16(zip,0);
    w16(zip,(uint16_t)entries.size()); w16(zip,(uint16_t)entries.size());
    w32(zip,cd_sz); w32(zip,cd_start); w16(zip,0);
    return zip;
}

static std::string sha256_hex_of(const void* p, size_t n) {
    uint8_t md[32];
    sha::sha256(p, n, md);
    return hex::encode(md,32);
}

static void write_file(const char* path, const std::vector<uint8_t>& data) {
    FILE* f=fopen(path,"wb"); assert(f);
    fwrite(data.data(),1,data.size(),f); fclose(f);
}

int main() {
    // Init SHA backend (dlopen BoringSSL on Android)
    assert(sha::ensure_initialized());

    const char STORED_DATA[] = "STORED_PAYLOAD_BYTES_FOR_TESTING";
    const uint32_t STORED_LEN = (uint32_t)strlen(STORED_DATA);
    const char DEFLATED_DATA[] = "DEFLATED_PAYLOAD_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const uint32_t DEFLATED_LEN = (uint32_t)strlen(DEFLATED_DATA);

    auto zip = build_zip(
        "stored.txt",   (const uint8_t*)STORED_DATA,   STORED_LEN,
        "deflated.txt", (const uint8_t*)DEFLATED_DATA, DEFLATED_LEN
    );
    const char* path = "/data/local/tmp/di_test_inflate.zip";
    write_file(path, zip);

    ApkMap apk; assert(apk.open(path));
    zip::CentralDirInfo cdi; assert(zip::find_central_directory(apk, &cdi));

    // Test 1: STORED entry — hash equals SHA-256 of the plain bytes
    {
        uint8_t out[32];
        bool ok = zip::hash_entry_decompressed(apk, cdi, "stored.txt", out);
        assert(ok);
        std::string want = sha256_hex_of(STORED_DATA, STORED_LEN);
        std::string got  = hex::encode(out, 32);
        assert(want == got && "Test1 STORED hash mismatch");
        printf("PASS test1: STORED hash = %s\n", got.c_str());
    }

    // Test 2: DEFLATED entry — hash equals SHA-256 of the INFLATED (plain) bytes
    {
        uint8_t out[32];
        bool ok = zip::hash_entry_decompressed(apk, cdi, "deflated.txt", out);
        assert(ok);
        std::string want = sha256_hex_of(DEFLATED_DATA, DEFLATED_LEN);
        std::string got  = hex::encode(out, 32);
        assert(want == got && "Test2 DEFLATED hash mismatch (got compressed hash?)");
        printf("PASS test2: DEFLATED decompressed hash = %s\n", got.c_str());
    }

    // Test 3: missing entry returns false, no crash
    {
        uint8_t out[32];
        bool ok = zip::hash_entry_decompressed(apk, cdi, "does_not_exist.bin", out);
        assert(!ok && "Test3 missing entry should return false");
        printf("PASS test3: missing entry returns false\n");
    }

    // Test 4: null entry_name returns false, no crash
    {
        uint8_t out[32];
        bool ok = zip::hash_entry_decompressed(apk, cdi, nullptr, out);
        assert(!ok && "Test4 null entry_name should return false");
        printf("PASS test4: null entry_name returns false\n");
    }

    // Test 5: garbage file (not a ZIP) — find_central_directory fails
    {
        const char* bad = "/data/local/tmp/di_garbage.bin";
        {FILE* f=fopen(bad,"wb"); const uint8_t g[]={0xDE,0xAD,0xBE,0xEF,0x00}; fwrite(g,1,4,f); fclose(f);}
        ApkMap bad_apk; bad_apk.open(bad);
        zip::CentralDirInfo bad_cdi;
        bool has_cd = zip::find_central_directory(bad_apk, &bad_cdi);
        if (has_cd) {
            uint8_t out[32];
            bool ok = zip::hash_entry_decompressed(bad_apk, bad_cdi, "anything", out);
            assert(!ok);
        }
        printf("PASS test5: garbage file handled safely (has_cd=%d)\n", (int)has_cd);
    }

    printf("ALL TESTS PASSED\n");
    return 0;
}
