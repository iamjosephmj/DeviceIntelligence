#include <cstdio>
#include <cstring>
#include "dicore/detectors/native_integrity/text_digest.hpp"
static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)
int main() {
    using namespace dicore::text_digest;
    uint8_t buf[8192]; for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i * 7);
    uint8_t d[32]; compute(buf, sizeof(buf), d);
    CHECK(verify(buf, sizeof(buf), d) == true);
    buf[5000] ^= 0x40;
    CHECK(verify(buf, sizeof(buf), d) == false);
    CHECK(count_mismatch_pages(buf, sizeof(buf), d) == SIZE_MAX);
    printf(fails ? "TEST-FAIL\n" : "TEST-OK\n");
    return fails ? 1 : 0;
}
