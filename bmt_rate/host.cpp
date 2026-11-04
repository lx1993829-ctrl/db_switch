// host.cpp -- run the bmt_rate kernel on the card and report BMT triple throughput.
//
//   bmt_rate.exe -x bmt_rate.xclbin [-d 0|<bdf>] [--cycles N] [--runs R]
//                [--mhz F] [--key0 HEX32] [--key1 HEX32]
//
// Each run: fresh 256-bit seed from the OS, kernel generates for N cycles with
// both FIFOs drained every cycle, then the host reads the counters and checks
// the first 4 captured triples: GCM decrypt + tag check with each server's
// key (and rejection under the other key), and (a0^a1) & (b0^b1) == c0^c1.

#include <xrt/xrt_bo.h>
#include <xrt/xrt_device.h>
#include <xrt/xrt_kernel.h>

#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr uint64_t kMagic      = 0x3145544152544D42ULL;  // "BMTRATE1"
constexpr size_t   kNcap       = 4;
constexpr size_t   kBeat       = 64;
constexpr size_t   kResultSize = (1 + 2 * kNcap) * kBeat;  // 576
constexpr size_t   kEntryBytes = 52;
constexpr size_t   kBoSize     = 4096;

struct Options {
    std::string xclbin = "bmt_rate.xclbin";
    std::string device = "0";
    uint64_t    cycles = 1000000000ULL;
    int         runs   = 3;
    double      mhz    = 0.0;  // 0: estimate from wall time
    // Must match AES_KEY_S0/S1 in src/bmt_rate.v
    std::string key0 = "000102030405060708090a0b0c0d0e0f";
    std::string key1 = "101112131415161718191a1b1c1d1e1f";
};

void usage(const char* argv0) {
    std::cerr << "usage: " << argv0
              << " -x <xclbin> [-d <index|bdf>] [--cycles N] [--runs R] [--mhz F]"
                 " [--key0 HEX32] [--key1 HEX32]\n";
}

Options parse_args(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + a);
            return argv[++i];
        };
        if (a == "-x" || a == "--xclbin")      o.xclbin = next();
        else if (a == "-d" || a == "--device") o.device = next();
        else if (a == "--cycles")              o.cycles = std::stoull(next());
        else if (a == "--runs")                o.runs = std::stoi(next());
        else if (a == "--mhz")                 o.mhz = std::stod(next());
        else if (a == "--key0")                o.key0 = next();
        else if (a == "--key1")                o.key1 = next();
        else if (a == "-h" || a == "--help") { usage(argv[0]); std::exit(0); }
        else throw std::runtime_error("unknown argument " + a);
    }
    if (o.cycles == 0) throw std::runtime_error("--cycles must be > 0");
    return o;
}

std::vector<uint8_t> hex_key(const std::string& h) {
    if (h.size() != 32) throw std::runtime_error("key must be 32 hex digits: " + h);
    std::vector<uint8_t> k(16);
    for (size_t i = 0; i < 16; ++i) k[i] = static_cast<uint8_t>(std::stoul(h.substr(2 * i, 2), nullptr, 16));
    return k;
}

xrt::device open_device(const std::string& d) {
    bool index = !d.empty() && std::all_of(d.begin(), d.end(), ::isdigit);
    return index ? xrt::device(static_cast<unsigned int>(std::stoul(d))) : xrt::device(d);
}

uint64_t le64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

uint64_t be64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

// entry = IV(12) | CT(24: CT0 16 + CT1 upper 8) | TAG(16). Returns false if the tag fails.
bool gcm_decrypt(const std::vector<uint8_t>& key, const uint8_t* entry, uint8_t pt[24]) {
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    int len = 0, len2 = 0;
    bool ok = EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(c, nullptr, nullptr, key.data(), entry) == 1 &&
              EVP_DecryptUpdate(c, pt, &len, entry + 12, 24) == 1 &&
              EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(entry + 36)) == 1 &&
              EVP_DecryptFinal_ex(c, pt + len, &len2) == 1;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

// Checks the captured triples; prints a line per failure. Returns true if all pass.
bool check_triples(const uint8_t* res, const std::vector<uint8_t>& k0, const std::vector<uint8_t>& k1) {
    bool pass = true;
    std::set<std::vector<uint8_t>> ivs;
    for (size_t k = 0; k < kNcap; ++k) {
        const uint8_t* e0 = res + (1 + k) * kBeat;
        const uint8_t* e1 = res + (1 + kNcap + k) * kBeat;
        uint8_t p0[24], p1[24], junk[24];

        bool ok0 = gcm_decrypt(k0, e0, p0);
        bool ok1 = gcm_decrypt(k1, e1, p1);
        if (!ok0) { std::printf("    triple %zu: server 0 share fails GCM with key0\n", k); pass = false; }
        if (!ok1) { std::printf("    triple %zu: server 1 share fails GCM with key1\n", k); pass = false; }
        if (gcm_decrypt(k1, e0, junk)) { std::printf("    triple %zu: server 0 share opens with key1\n", k); pass = false; }
        if (gcm_decrypt(k0, e1, junk)) { std::printf("    triple %zu: server 1 share opens with key0\n", k); pass = false; }
        ivs.insert(std::vector<uint8_t>(e0, e0 + 12));
        ivs.insert(std::vector<uint8_t>(e1, e1 + 12));
        if (!ok0 || !ok1) continue;

        // plaintext = a | b | c, 64-bit big-endian each
        uint64_t a = be64(p0) ^ be64(p1);
        uint64_t b = be64(p0 + 8) ^ be64(p1 + 8);
        uint64_t c = be64(p0 + 16) ^ be64(p1 + 16);
        if ((a & b) != c) {
            std::printf("    triple %zu: c != a & b  (a=%016llx b=%016llx c=%016llx)\n", k,
                        (unsigned long long)a, (unsigned long long)b, (unsigned long long)c);
            pass = false;
        }
        if (a == 0 && b == 0) { std::printf("    triple %zu: a = b = 0\n", k); pass = false; }
    }
    if (ivs.size() != 2 * kNcap) { std::printf("    repeated GCM IV among captured entries\n"); pass = false; }
    return pass;
}

}  // namespace

int main(int argc, char** argv) {
    Options o;
    try {
        o = parse_args(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        usage(argv[0]);
        return 2;
    }

    try {
        auto key0 = hex_key(o.key0);
        auto key1 = hex_key(o.key1);

        auto dev  = open_device(o.device);
        auto uuid = dev.load_xclbin(o.xclbin);
        xrt::kernel krnl(dev, uuid, "bmt_rate");
        xrt::bo out(dev, kBoSize, krnl.group_id(5));

        std::random_device rd;  // /dev/urandom on Linux
        auto rnd64 = [&]() { return (static_cast<uint64_t>(rd()) << 32) | rd(); };
        std::vector<uint8_t> zeros(kBoSize, 0), res(kResultSize);

        std::printf("bmt_rate: %llu cycles per run, %d run(s)\n", (unsigned long long)o.cycles, o.runs);
        bool all_pass = true;
        double sum_tps = 0.0;

        for (int r = 1; r <= o.runs; ++r) {
            uint64_t seed[4];
            do {
                for (auto& s : seed) s = rnd64();
            } while ((seed[0] | seed[1] | seed[2] | seed[3]) == 0);  // bmt_pregen ignores a zero seed

            out.write(zeros.data(), kBoSize, 0);
            out.sync(XCL_BO_SYNC_BO_TO_DEVICE);

            auto t0  = std::chrono::steady_clock::now();
            auto run = krnl(o.cycles, seed[0], seed[1], seed[2], seed[3], out);
            auto st  = run.wait();
            auto t1  = std::chrono::steady_clock::now();
            if (st != ERT_CMD_STATE_COMPLETED) throw std::runtime_error("kernel run did not complete");
            double wall = std::chrono::duration<double>(t1 - t0).count();

            out.sync(XCL_BO_SYNC_BO_FROM_DEVICE);
            out.read(res.data(), kResultSize, 0);

            const uint8_t* h = res.data();
            uint64_t magic = le64(h), cycles = le64(h + 8), pops0 = le64(h + 16), pops1 = le64(h + 24);
            uint64_t first = le64(h + 32), last = le64(h + 40);
            if (magic != kMagic) throw std::runtime_error("result block has wrong magic (kernel did not write it)");
            if (cycles != o.cycles) throw std::runtime_error("kernel cycle count differs from the requested run length");

            double mhz = o.mhz > 0 ? o.mhz : cycles / wall / 1e6;
            std::printf("\nrun %d\n", r);
            std::printf("  triples          : %llu (server 0)  %llu (server 1)%s\n",
                        (unsigned long long)pops0, (unsigned long long)pops1,
                        pops0 == pops1 ? "" : "   <-- MISMATCH");
            if (pops0 < 2) {
                std::printf("  too few triples to measure a rate (run longer)\n");
                all_pass = false;
                continue;
            }
            double cpt_steady = double(last - first) / double(pops0 - 1);
            double tps        = pops0 * mhz * 1e6 / cycles;
            sum_tps += tps;
            std::printf("  first triple     : cycle %llu (cold start)\n", (unsigned long long)first);
            std::printf("  cycles / triple  : %.2f steady state, %.2f overall\n", cpt_steady, double(cycles) / pops0);
            std::printf("  kernel clock     : %.2f MHz (%s)\n", mhz,
                        o.mhz > 0 ? "--mhz" : "estimated from wall time");
            std::printf("  throughput       : %.3f M triples/s (each = 1 share per server)\n", tps / 1e6);
            std::printf("  encrypted output : %.1f MB/s (2 x %zu B per triple)\n",
                        tps * 2 * kEntryBytes / 1e6, kEntryBytes);
            if (o.mhz <= 0 && wall < 0.5)
                std::printf("  note: run < 0.5 s, clock estimate is rough; use more --cycles or --mhz\n");

            bool pass = (pops0 == pops1) && check_triples(res.data(), key0, key1);
            std::printf("  triple check     : %s (first %zu triples: GCM tags, key separation, c = a & b)\n",
                        pass ? "PASS" : "FAIL", kNcap);
            all_pass = all_pass && pass;
        }

        if (o.runs > 0)
            std::printf("\nmean throughput: %.3f M triples/s over %d run(s)\n", sum_tps / o.runs / 1e6, o.runs);
        std::printf("%s\n", all_pass ? "PASS" : "FAIL");
        return all_pass ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
