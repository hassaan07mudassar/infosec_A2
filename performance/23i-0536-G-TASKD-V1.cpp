// Hassaan Mudassar — 23i-0536 — CS3002 Information Security — Assignment 2
// Roll: 23i-0536   Section: G
// Part D: Performance measurement tooling (v1 vs v2 comparison)

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <cmath>
#include <numeric>
#include <iomanip>
#include <thread>
#include <atomic>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// Include v1 and v2 headers
#include "../smartlock/slink.hpp"
#include "../v2_skeleton/securelink2.hpp"
#include "../v2_skeleton/dh2048.hpp"
#include "../v2_skeleton/pki.hpp"

using namespace std::chrono;

struct Stats {
    double mean = 0.0;
    double stddev = 0.0;
    double min_val = 0.0;
    double max_val = 0.0;
};

static Stats compute_stats(const std::vector<double>& v) {
    Stats s;
    if (v.empty()) return s;
    double sum = std::accumulate(v.begin(), v.end(), 0.0);
    s.mean = sum / v.size();
    s.min_val = v[0];
    s.max_val = v[0];
    double var_sum = 0.0;
    for (double x : v) {
        var_sum += (x - s.mean) * (x - s.mean);
        if (x < s.min_val) s.min_val = x;
        if (x > s.max_val) s.max_val = x;
    }
    s.stddev = (v.size() > 1) ? std::sqrt(var_sum / (v.size() - 1)) : 0.0;
    return s;
}

// =========================================================================
// 1. Handshake Benchmark (v1 vs v2)
// =========================================================================

// Runs an in-memory loopback socket handshake for v1
static double run_handshake_v1(const std::map<std::string, std::string>& cfg) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 0.0;

    auto t0 = high_resolution_clock::now();

    // Server thread (v1 handshake)
    std::thread server_th([&]() {
        slink::Reader r(sv[0]);
        slink::Msg m;
        if (!r.recv(m)) return; // HELLO
        slink::send_msg(sv[0], {{"type","SUITE"},{"suite","AES256-GCM"}});
        std::string pub_pem = slink::b64dec(cfg.at("rsa_pub_b64"));
        slink::send_msg(sv[0], {{"type","CERT"},{"name",cfg.at("device_name")},{"pubkey",slink::b64enc(pub_pem)}});
        if (!r.recv(m)) return; // PAIR
        slink::send_msg(sv[0], {{"type","DH"},{"B",cfg.at("dh_B")}});
        if (!r.recv(m)) return; // DHCLIENT
        uint64_t A = std::stoull(m["A"]);
        uint64_t b = std::stoull(cfg.at("dh_b"));
        uint64_t p = std::stoull(cfg.at("dh_p"));
        uint64_t shared = slink::modexp(A, b, p);
        auto key = slink::session_key(shared, "AES256-GCM");
        auto nonce = slink::from_hex(cfg.at("static_nonce"));
        auto enc = slink::record_encrypt("AES256-GCM", key, nonce, "Paired greeting " + cfg.at("flag"));
        slink::send_msg(sv[0], {{"type","MSG"},{"rec",slink::to_hex(enc)}});
        close(sv[0]);
    });

    // Client execution (v1 handshake)
    slink::Reader r(sv[1]);
    slink::Msg m;
    slink::send_msg(sv[1], {{"type","HELLO"},{"suites","AES256-GCM,AES128-GCM,NULL"}});
    r.recv(m); // SUITE
    r.recv(m); // CERT
    slink::send_msg(sv[1], {{"type","PAIR"},{"hub","home-hub"},{"pinhash",cfg.at("pin_md5")}});
    r.recv(m); // DH
    uint64_t B = std::stoull(m["B"]);
    uint64_t a = 123456789ULL;
    uint64_t p = std::stoull(cfg.at("dh_p"));
    uint64_t g = std::stoull(cfg.at("dh_g"));
    uint64_t A = slink::modexp(g, a, p);
    slink::send_msg(sv[1], {{"type","DHCLIENT"},{"A",std::to_string(A)}});
    uint64_t shared = slink::modexp(B, a, p);
    auto key = slink::session_key(shared, "AES256-GCM");
    r.recv(m); // MSG greeting
    auto nonce = slink::from_hex(cfg.at("static_nonce"));
    std::string pt = slink::record_decrypt("AES256-GCM", key, nonce, slink::from_hex(m["rec"]));

    auto t1 = high_resolution_clock::now();
    close(sv[1]);
    server_th.join();

    return duration<double, std::milli>(t1 - t0).count();
}

// Runs an in-memory loopback socket handshake for v2
static double run_handshake_v2(const std::map<std::string, std::string>& cfg) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 0.0;

    auto t0 = high_resolution_clock::now();

    // Server thread (v2 handshake)
    std::thread server_th([&]() {
        slink::Reader r(sv[0]);
        slink::Msg m;
        if (!r.recv(m)) return; // HELLO
        std::string offered = m["suites"];
        std::string suite = "AES256-GCM";
        slink::send_msg(sv[0], {{"type","SUITE"},{"suite",suite}});

        std::string pub_pem = slink::b64dec(cfg.at("rsa_pub_b64"));
        EVP_PKEY* priv = pki::load_priv(slink::b64dec(cfg.at("rsa_priv_b64")));
        auto certsig = pki::sign(priv, cfg.at("device_name") + pub_pem);
        slink::send_msg(sv[0], {{"type","CERT"},{"name",cfg.at("device_name")},
                                {"pubkey",slink::b64enc(pub_pem)},{"sig",slink::to_hex(certsig)}});
        if (!r.recv(m)) { EVP_PKEY_free(priv); return; } // PAIR

        std::string dpriv, dpub;
        dh2048::keygen(dpriv, dpub);
        std::string transcript = offered + "|" + suite + "|" + dpub;
        auto dhsig = pki::sign(priv, transcript);
        slink::send_msg(sv[0], {{"type","DH"},{"B",dpub},{"sig",slink::to_hex(dhsig)}});
        EVP_PKEY_free(priv);

        if (!r.recv(m)) return; // DHCLIENT
        auto shared = dh2048::shared(m["A"], dpriv);
        auto k_s2c = sl2::derive_key(shared, suite, "s2c");
        auto rec = sl2::seal(k_s2c, 0, "Paired greeting " + cfg.at("flag"));
        slink::send_msg(sv[0], {{"type","MSG"},{"rec",slink::to_hex(rec)}});
        close(sv[0]);
    });

    // Client execution (v2 handshake)
    slink::Reader r(sv[1]);
    slink::Msg m;
    std::string offer = "AES256-GCM,AES128-GCM";
    slink::send_msg(sv[1], {{"type","HELLO"},{"suites",offer}});
    r.recv(m); // SUITE
    std::string suite = m["suite"];
    r.recv(m); // CERT
    std::string pub_pem = slink::b64dec(m["pubkey"]);
    EVP_PKEY* dev = pki::load_pub(pub_pem);
    pki::verify(dev, m["name"] + pub_pem, slink::from_hex(m["sig"]));
    slink::send_msg(sv[1], {{"type","PAIR"},{"hub","home-hub"},{"pinhash",cfg.at("pin_md5")}});

    r.recv(m); // DH
    std::string B = m["B"];
    std::string transcript = offer + "|" + suite + "|" + B;
    pki::verify(dev, transcript, slink::from_hex(m["sig"]));
    EVP_PKEY_free(dev);

    std::string apriv, apub;
    dh2048::keygen(apriv, apub);
    slink::send_msg(sv[1], {{"type","DHCLIENT"},{"A",apub}});
    auto shared = dh2048::shared(B, apriv);
    auto k_s2c = sl2::derive_key(shared, suite, "s2c");

    r.recv(m); // MSG
    std::string pt = sl2::open_record(k_s2c, slink::from_hex(m["rec"]), 0);

    auto t1 = high_resolution_clock::now();
    close(sv[1]);
    server_th.join();

    return duration<double, std::milli>(t1 - t0).count();
}

// =========================================================================
// 2. Per-Record Overhead & Latency Benchmark
// =========================================================================
struct RecordBench {
    size_t wire_extra_bytes;
    Stats seal_us;
    Stats open_us;
};

static RecordBench bench_records_v1(size_t trials) {
    std::vector<uint8_t> key(32, 0x22);
    std::vector<uint8_t> nonce(12, 0x33);
    std::string sample = "UNLOCK DOOR command test payload seq=100";

    // Extra bytes on wire: ciphertext(len) + tag(16) vs plaintext(len) => +16 bytes
    auto rec = slink::record_encrypt("AES256-GCM", key, nonce, sample);
    size_t wire_extra = rec.size() - sample.size();

    std::vector<double> seal_times, open_times;
    seal_times.reserve(trials);
    open_times.reserve(trials);

    for (size_t i = 0; i < trials; ++i) {
        auto t0 = high_resolution_clock::now();
        auto enc = slink::record_encrypt("AES256-GCM", key, nonce, sample);
        auto t1 = high_resolution_clock::now();
        auto dec = slink::record_decrypt("AES256-GCM", key, nonce, enc);
        auto t2 = high_resolution_clock::now();

        seal_times.push_back(duration<double, std::micro>(t1 - t0).count());
        open_times.push_back(duration<double, std::micro>(t2 - t1).count());
    }

    return {wire_extra, compute_stats(seal_times), compute_stats(open_times)};
}

static RecordBench bench_records_v2(size_t trials) {
    std::vector<uint8_t> key(32, 0x22);
    std::string sample = "UNLOCK DOOR command test payload seq=100";

    // Extra bytes on wire: seqno(8) + ciphertext(len) + tag(16) vs plaintext(len) => +24 bytes
    auto rec = sl2::seal(key, 100, sample);
    size_t wire_extra = rec.size() - sample.size();

    std::vector<double> seal_times, open_times;
    seal_times.reserve(trials);
    open_times.reserve(trials);

    for (size_t i = 0; i < trials; ++i) {
        auto t0 = high_resolution_clock::now();
        auto enc = sl2::seal(key, 100 + i, sample);
        auto t1 = high_resolution_clock::now();
        auto dec = sl2::open_record(key, enc, 100 + i);
        auto t2 = high_resolution_clock::now();

        seal_times.push_back(duration<double, std::micro>(t1 - t0).count());
        open_times.push_back(duration<double, std::micro>(t2 - t1).count());
    }

    return {wire_extra, compute_stats(seal_times), compute_stats(open_times)};
}

// =========================================================================
// 3. Throughput Benchmark (1 KiB records, >= 10,000 records/run, >= 5 runs)
// =========================================================================
static Stats bench_throughput_v1(size_t runs, size_t count) {
    std::vector<uint8_t> key(32, 0x22);
    std::vector<uint8_t> nonce(12, 0x33);
    std::string pt(1024, 'A'); // 1 KiB
    double total_mb = (double)(count * 1024) / (1024.0 * 1024.0);

    std::vector<double> rates;
    for (size_t r = 0; r < runs; ++r) {
        auto t0 = high_resolution_clock::now();
        for (size_t i = 0; i < count; ++i) {
            auto enc = slink::record_encrypt("AES256-GCM", key, nonce, pt);
            auto dec = slink::record_decrypt("AES256-GCM", key, nonce, enc);
        }
        auto t1 = high_resolution_clock::now();
        double elapsed_sec = duration<double>(t1 - t0).count();
        rates.push_back(total_mb / elapsed_sec);
    }
    return compute_stats(rates);
}

static Stats bench_throughput_v2(size_t runs, size_t count) {
    std::vector<uint8_t> key(32, 0x22);
    std::string pt(1024, 'A'); // 1 KiB
    double total_mb = (double)(count * 1024) / (1024.0 * 1024.0);

    std::vector<double> rates;
    for (size_t r = 0; r < runs; ++r) {
        auto t0 = high_resolution_clock::now();
        for (size_t i = 0; i < count; ++i) {
            auto enc = sl2::seal(key, i, pt);
            auto dec = sl2::open_record(key, enc, i);
        }
        auto t1 = high_resolution_clock::now();
        double elapsed_sec = duration<double>(t1 - t0).count();
        rates.push_back(total_mb / elapsed_sec);
    }
    return compute_stats(rates);
}

// =========================================================================
// Main Runner
// =========================================================================
int main(int argc, char** argv) {
    std::string cfg_path = (argc > 1) ? argv[1] : "../smartlock/instance.txt";
    auto cfg = slink::read_config(cfg_path);

    std::cout << "======================================================================\n";
    std::cout << " CS3002 Assignment 2 - Part D Performance Benchmark (Hassaan Mudassar)\n";
    std::cout << " Roll: 23i-0536   Section: G\n";
    std::cout << " Comparing: SmartLock v1 (baseline) vs SmartLock v2 (hardened)\n";
    std::cout << "======================================================================\n\n";

    // 1. Handshake latency (30 runs each)
    const int kHandshakeRuns = 35;
    std::cout << "[1/3] Benchmarking Handshake Latency (" << kHandshakeRuns << " runs each)...\n";
    std::vector<double> hs_v1, hs_v2;
    for (int i = 0; i < kHandshakeRuns; ++i) {
        hs_v1.push_back(run_handshake_v1(cfg));
        hs_v2.push_back(run_handshake_v2(cfg));
    }
    Stats stats_hs_v1 = compute_stats(hs_v1);
    Stats stats_hs_v2 = compute_stats(hs_v2);

    // 2. Per-record overhead
    const size_t kRecordTrials = 10000;
    std::cout << "[2/3] Benchmarking Per-Record Overhead (" << kRecordTrials << " iterations)...\n";
    auto rb_v1 = bench_records_v1(kRecordTrials);
    auto rb_v2 = bench_records_v2(kRecordTrials);

    // 3. Throughput (5 runs x 10,000 1 KiB records)
    const size_t kTPRuns = 5;
    const size_t kTPRecords = 10000;
    std::cout << "[3/3] Benchmarking 1 KiB Record Throughput (" << kTPRuns << " runs x " << kTPRecords << " records)...\n\n";
    auto tp_v1 = bench_throughput_v1(kTPRuns, kTPRecords);
    auto tp_v2 = bench_throughput_v2(kTPRuns, kTPRecords);

    // =====================================================================
    // Report Summary Output
    // =====================================================================
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "======================================================================\n";
    std::cout << " PART D PERFORMANCE BENCHMARK RESULTS TABLE\n";
    std::cout << "======================================================================\n";
    std::cout << std::left << std::setw(30) << "Metric" 
              << std::setw(20) << "v1 (Baseline)" 
              << std::setw(20) << "v2 (Hardened)" 
              << "Cost / Difference\n";
    std::cout << "----------------------------------------------------------------------\n";

    std::cout << std::left << std::setw(30) << "Handshake Latency (mean)" 
              << (std::to_string(stats_hs_v1.mean) + " ms") 
              << std::setw(20 - (std::to_string(stats_hs_v1.mean).size() + 3)) << ""
              << (std::to_string(stats_hs_v2.mean) + " ms") 
              << std::setw(20 - (std::to_string(stats_hs_v2.mean).size() + 3)) << ""
              << "+" << (stats_hs_v2.mean - stats_hs_v1.mean) << " ms (" 
              << (stats_hs_v2.mean / stats_hs_v1.mean) << "x)\n";

    std::cout << std::left << std::setw(30) << "Handshake StdDev (sigma)" 
              << (std::to_string(stats_hs_v1.stddev) + " ms") 
              << std::setw(20 - (std::to_string(stats_hs_v1.stddev).size() + 3)) << ""
              << (std::to_string(stats_hs_v2.stddev) + " ms") << "\n";

    std::cout << std::left << std::setw(30) << "Wire Overhead per Record" 
              << "+" + std::to_string(rb_v1.wire_extra_bytes) + " bytes"
              << std::setw(20 - (std::to_string(rb_v1.wire_extra_bytes).size() + 7)) << ""
              << "+" + std::to_string(rb_v2.wire_extra_bytes) + " bytes"
              << std::setw(20 - (std::to_string(rb_v2.wire_extra_bytes).size() + 7)) << ""
              << "+" << (rb_v2.wire_extra_bytes - rb_v1.wire_extra_bytes) << " bytes (seqno)\n";

    std::cout << std::left << std::setw(30) << "Record Seal Time (mean)" 
              << (std::to_string(rb_v1.seal_us.mean) + " us") 
              << std::setw(20 - (std::to_string(rb_v1.seal_us.mean).size() + 3)) << ""
              << (std::to_string(rb_v2.seal_us.mean) + " us") 
              << std::setw(20 - (std::to_string(rb_v2.seal_us.mean).size() + 3)) << ""
              << "+" << (rb_v2.seal_us.mean - rb_v1.seal_us.mean) << " us\n";

    std::cout << std::left << std::setw(30) << "Record Open Time (mean)" 
              << (std::to_string(rb_v1.open_us.mean) + " us") 
              << std::setw(20 - (std::to_string(rb_v1.open_us.mean).size() + 3)) << ""
              << (std::to_string(rb_v2.open_us.mean) + " us") 
              << std::setw(20 - (std::to_string(rb_v2.open_us.mean).size() + 3)) << ""
              << "+" << (rb_v2.open_us.mean - rb_v1.open_us.mean) << " us\n";

    std::cout << std::left << std::setw(30) << "1 KiB Throughput (mean)" 
              << (std::to_string(tp_v1.mean) + " MB/s") 
              << std::setw(20 - (std::to_string(tp_v1.mean).size() + 5)) << ""
              << (std::to_string(tp_v2.mean) + " MB/s") 
              << std::setw(20 - (std::to_string(tp_v2.mean).size() + 5)) << ""
              << (tp_v2.mean / tp_v1.mean * 100.0) << "% of baseline\n";

    std::cout << std::left << std::setw(30) << "Throughput StdDev (sigma)" 
              << (std::to_string(tp_v1.stddev) + " MB/s") 
              << std::setw(20 - (std::to_string(tp_v1.stddev).size() + 5)) << ""
              << (std::to_string(tp_v2.stddev) + " MB/s") << "\n";

    std::cout << "======================================================================\n\n";

    return 0;
}

