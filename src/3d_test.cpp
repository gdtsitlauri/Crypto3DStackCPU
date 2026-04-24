#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "3d.h"
#include "header.h"

// Top function exposed for software simulation and HLS integration tests.
extern "C" void Crypto3DStackCPU_top(volatile uint32_t* image,
                                      uint32_t word_count,
                                      volatile uint32_t* status_word);

// Globals provided by 3d.cpp.
extern StackedMemory3D stackedMemory;
extern uint32_t reg_file[NUM_REGS];

namespace {

constexpr uint32_t EXPECTED_SIGNATURE = 0x000000AEu;
constexpr uint32_t DEMO_SIGNATURE_DATA_OFFSET = 0u;
constexpr uint32_t STATUS_SECURITY_LOCK = 0x00000001u;
constexpr uint32_t STATUS_KEY_FAILURE   = 0x00000002u;

struct ValidationContract {
    bool signature_enabled = true;
    bool signature_pre_zero = true;
    uint32_t signature_offset = DEMO_SIGNATURE_DATA_OFFSET;
    uint32_t signature_expected = EXPECTED_SIGNATURE;

    bool status_expect_clean = true;
    bool image_pre_validate = true;
    bool image_post_validate = true;
    bool output_reload_validate = true;
    uint32_t status_min_retired = 1u;
    uint32_t status_max_retired = 0u; // 0 means no upper bound.

    std::array<bool, NUM_REGS> reg_enabled{};
    std::array<uint32_t, NUM_REGS> reg_expected{};
};

struct Options {
    std::string image_path = "demo.hex";
    std::string contract_path;
    std::string output_image_path;
    bool explicit_contract = false;
    bool verbose = false;
    bool dump_memory = false;
    bool run_memory_self_test = false;
};

static std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }

    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }

    return s.substr(start, end - start);
}

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static std::string stripComment(const std::string& line) {
    const size_t hash = line.find('#');
    return (hash == std::string::npos) ? line : line.substr(0, hash);
}

static bool parseBool(const std::string& token, bool& value) {
    const std::string t = toLower(trim(token));
    if (t == "1" || t == "true" || t == "yes" || t == "on") {
        value = true;
        return true;
    }
    if (t == "0" || t == "false" || t == "no" || t == "off") {
        value = false;
        return true;
    }
    return false;
}

static bool parseU32(const std::string& token, uint32_t& value) {
    const std::string t = trim(token);
    if (t.empty()) return false;

    try {
        size_t idx = 0;
        unsigned long parsed = std::stoul(t, &idx, 0);
        if (idx != t.size()) return false;
        value = static_cast<uint32_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

static bool parseHexWord(const std::string& token, uint32_t& value) {
    const std::string t = trim(token);
    if (t.empty()) return false;

    try {
        size_t idx = 0;
        unsigned long parsed = std::stoul(t, &idx, 16);
        if (idx != t.size()) return false;
        value = static_cast<uint32_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

static void printDivider(const std::string& title) {
    std::cout << "\n================ " << title << " ================\n";
}

static ValidationContract defaultContract() {
    ValidationContract c;
    c.reg_enabled.fill(false);
    c.reg_expected.fill(0u);

    // Built-in demo contract. For non-demo programs, pass an explicit .contract.
    c.reg_enabled[2]  = true; c.reg_expected[2]  = 0x00000001u;
    c.reg_enabled[3]  = true; c.reg_expected[3]  = 0x00000002u;
    c.reg_enabled[4]  = true; c.reg_expected[4]  = 0x00000003u;
    c.reg_enabled[5]  = true; c.reg_expected[5]  = 0x00000004u;
    c.reg_enabled[6]  = true; c.reg_expected[6]  = 0x00000005u;
    c.reg_enabled[7]  = true; c.reg_expected[7]  = 0x00000006u;
    c.reg_enabled[8]  = true; c.reg_expected[8]  = EXPECTED_SIGNATURE;
    c.reg_enabled[11] = true; c.reg_expected[11] = 0x00000005u;
    return c;
}

static bool loadContract(const std::string& path, ValidationContract& contract, std::string& err) {
    std::ifstream fin(path);
    if (!fin) {
        err = "Cannot open contract file: " + path;
        return false;
    }

    std::string line;
    int line_no = 0;
    while (std::getline(fin, line)) {
        ++line_no;
        line = trim(stripComment(line));
        if (line.empty()) continue;

        const size_t eq = line.find('=');
        if (eq == std::string::npos) {
            err = "Contract line " + std::to_string(line_no) + ": missing '='";
            return false;
        }

        const std::string key = toLower(trim(line.substr(0, eq)));
        const std::string value = trim(line.substr(eq + 1));

        auto parse_bool_key = [&](bool& field, const char* name) -> bool {
            bool parsed = false;
            if (!parseBool(value, parsed)) {
                err = "Contract line " + std::to_string(line_no) + ": invalid bool for " + name;
                return false;
            }
            field = parsed;
            return true;
        };

        auto parse_u32_key = [&](uint32_t& field, const char* name) -> bool {
            uint32_t parsed = 0u;
            if (!parseU32(value, parsed)) {
                err = "Contract line " + std::to_string(line_no) + ": invalid value for " + name;
                return false;
            }
            field = parsed;
            return true;
        };

        if (key == "signature.enabled") {
            if (!parse_bool_key(contract.signature_enabled, "signature.enabled")) return false;
            continue;
        }
        if (key == "signature.pre_zero") {
            if (!parse_bool_key(contract.signature_pre_zero, "signature.pre_zero")) return false;
            continue;
        }
        if (key == "signature.offset") {
            if (!parse_u32_key(contract.signature_offset, "signature.offset")) return false;
            continue;
        }
        if (key == "signature.expected") {
            if (!parse_u32_key(contract.signature_expected, "signature.expected")) return false;
            continue;
        }
        if (key == "status.expect_clean") {
            if (!parse_bool_key(contract.status_expect_clean, "status.expect_clean")) return false;
            continue;
        }
        if (key == "status.min_retired") {
            if (!parse_u32_key(contract.status_min_retired, "status.min_retired")) return false;
            continue;
        }
        if (key == "status.max_retired") {
            if (!parse_u32_key(contract.status_max_retired, "status.max_retired")) return false;
            continue;
        }
        if (key == "image.pre_validate") {
            if (!parse_bool_key(contract.image_pre_validate, "image.pre_validate")) return false;
            continue;
        }
        if (key == "image.post_validate") {
            if (!parse_bool_key(contract.image_post_validate, "image.post_validate")) return false;
            continue;
        }
        if (key == "output.reload_validate" || key == "image.reload_validate") {
            if (!parse_bool_key(contract.output_reload_validate, "output.reload_validate")) return false;
            continue;
        }

        if (key == "registers.enabled" || key == "regs.enabled") {
            bool flag = false;
            if (!parseBool(value, flag)) {
                err = "Contract line " + std::to_string(line_no) + ": invalid bool for registers.enabled";
                return false;
            }
            if (!flag) contract.reg_enabled.fill(false);
            continue;
        }

        if (key.rfind("reg.", 0) == 0) {
            const std::string idx_token = key.substr(4);
            int reg_idx = -1;
            try {
                size_t idx = 0;
                reg_idx = std::stoi(idx_token, &idx, 10);
                if (idx != idx_token.size()) {
                    err = "Contract line " + std::to_string(line_no) + ": invalid register index";
                    return false;
                }
            } catch (...) {
                err = "Contract line " + std::to_string(line_no) + ": invalid register index";
                return false;
            }

            if (reg_idx < 0 || reg_idx >= NUM_REGS) {
                err = "Contract line " + std::to_string(line_no) + ": register index out of range";
                return false;
            }

            uint32_t parsed = 0u;
            if (!parseU32(value, parsed)) {
                err = "Contract line " + std::to_string(line_no) + ": invalid register expected value";
                return false;
            }

            contract.reg_enabled[static_cast<size_t>(reg_idx)] = true;
            contract.reg_expected[static_cast<size_t>(reg_idx)] = parsed;
            continue;
        }

        err = "Contract line " + std::to_string(line_no) + ": unknown key '" + key + "'";
        return false;
    }

    return true;
}

static bool parseOptions(int argc, char** argv, Options& opt, std::string& err) {
    std::vector<std::string> positional;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--verbose" || arg == "-v") {
            opt.verbose = true;
        } else if (arg == "--dump") {
            opt.dump_memory = true;
        } else if (arg == "--memory-self-test") {
            opt.run_memory_self_test = true;
        } else if (arg == "--write-output") {
            if (i + 1 >= argc) {
                err = "--write-output requires a path";
                return false;
            }
            opt.output_image_path = argv[++i];
        } else if (arg.rfind("--write-output=", 0) == 0) {
            opt.output_image_path = arg.substr(std::string("--write-output=").size());
            if (opt.output_image_path.empty()) {
                err = "--write-output requires a non-empty path";
                return false;
            }
        } else if (arg == "--help" || arg == "-h") {
            err.clear();
            return false;
        } else if (!arg.empty() && arg[0] == '-') {
            err = "Unknown option: " + arg;
            return false;
        } else {
            positional.push_back(arg);
        }
    }

    if (!positional.empty()) opt.image_path = positional[0];
    if (positional.size() >= 2) {
        opt.contract_path = positional[1];
        opt.explicit_contract = true;
    }
    if (positional.size() > 2) {
        err = "Too many positional arguments";
        return false;
    }

    return true;
}

static void printUsage(const char* argv0) {
    std::cerr
        << "Usage: " << argv0 << " [image.hex] [contract] [options]\n\n"
        << "Options:\n"
        << "  --write-output <path>   Save post-execution resealed image\n"
        << "  --verbose               Print additional execution details\n"
        << "  --dump                  Dump selected memory/register values\n"
        << "  --memory-self-test      Run optional memory/AES feature checks after proof\n";
}

static bool loadHexImage(const std::string& path, std::vector<uint32_t>& image, std::string& err) {
    std::ifstream fin(path);
    if (!fin) {
        err = "Cannot open image file: " + path;
        return false;
    }

    image.clear();
    std::string raw;
    uint32_t line_no = 0u;
    while (std::getline(fin, raw)) {
        ++line_no;
        const std::string line = trim(stripComment(raw));
        if (line.empty()) continue;

        uint32_t word = 0u;
        if (!parseHexWord(line, word)) {
            err = "Invalid hex word at line " + std::to_string(line_no) + ": " + line;
            return false;
        }

        if (image.size() >= MEM_SIZE) {
            err = "Input image exceeds MEM_SIZE=" + std::to_string(MEM_SIZE) + " words";
            return false;
        }

        image.push_back(word);
    }

    if (image.empty()) {
        err = "Input image is empty";
        return false;
    }

    if (image.size() < MEM_SIZE) {
        image.resize(MEM_SIZE, 0u);
    }

    return true;
}

static bool writeHexImage(const std::string& path, const std::vector<uint32_t>& image, std::string& err) {
    std::ofstream fout(path);
    if (!fout) {
        err = "Cannot write output image: " + path;
        return false;
    }

    for (uint32_t word : image) {
        fout << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << word << '\n';
    }

    return true;
}

static void loadImageIntoStackedMemory(const std::vector<uint32_t>& image) {
    if (stackedMemory.isSecurityLocked()) {
        stackedMemory.clearSecurityLockdown();
    }

    const size_t n = std::min<size_t>(image.size(), MEM_SIZE);
    for (size_t i = 0; i < n; ++i) {
        if (i < SEC_HDR_WORDS) {
            stackedMemory.protectedWrite(0, i, image[i]);
        } else {
            stackedMemory.write(0, i, image[i]);
        }
    }

    for (size_t i = n; i < MEM_SIZE; ++i) {
        if (i < SEC_HDR_WORDS) {
            stackedMemory.protectedWrite(0, i, 0u);
        } else {
            stackedMemory.write(0, i, 0u);
        }
    }
}

static bool getSignatureAddress(const ValidationContract& contract, uint32_t& signature_addr, std::string& err) {
    uint32_t data_start = 0u;
    uint32_t data_words = 0u;
    uint32_t data_end = 0u;
    uint32_t data_flags = 0u;
    const int rc = secure_get_data_region(&data_start, &data_words, &data_end, &data_flags);
    if (rc != 0) {
        err = "secure_get_data_region failed with rc=" + std::to_string(rc);
        return false;
    }

    if (contract.signature_offset >= data_words) {
        err = "Signature offset " + std::to_string(contract.signature_offset) +
              " is outside data_words=" + std::to_string(data_words);
        return false;
    }

    signature_addr = data_start + contract.signature_offset;
    if (signature_addr >= MEM_SIZE || signature_addr >= data_end) {
        err = "Computed signature address is outside data region";
        return false;
    }

    return true;
}

static void dumpMemory(size_t offset, size_t words) {
    const size_t end = std::min<size_t>(offset + words, MEM_SIZE);
    std::cout << "Dump layer 0 words " << std::dec << offset << "-" << (end ? end - 1 : 0) << ":\n";
    for (size_t i = offset; i < end; ++i) {
        const uint32_t value = (i < SEC_HDR_WORDS) ? stackedMemory.protectedRead(0, i) : stackedMemory.read(0, i);
        std::cout << "L0[" << std::dec << std::setw(3) << i << "] = 0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << value << std::setfill(' ') << std::dec << '\n';
    }
}

static void dumpRegisters() {
    for (int i = 0; i < NUM_REGS; ++i) {
        std::cout << "reg[" << std::dec << std::setw(2) << i << "] = 0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << reg_file[i] << std::setfill(' ') << std::dec << '\n';
    }
}

static bool runAesKnownAnswerTest() {
    uint32_t key[4] = {
        0x00010203u, 0x04050607u, 0x08090A0Bu, 0x0C0D0E0Fu
    };
    uint32_t plain[4] = {
        0x00112233u, 0x44556677u, 0x8899AABBu, 0xCCDDEEFFu
    };
    const uint32_t expected[4] = {
        0x69C4E0D8u, 0x6A7B0430u, 0xD8CDB780u, 0x70B4C55Au
    };
    uint32_t cipher[4] = {0u, 0u, 0u, 0u};
    uint32_t decoded[4] = {0u, 0u, 0u, 0u};

    aes_encrypt_block(plain, key, cipher);
    bool enc_ok = true;
    for (int i = 0; i < 4; ++i) {
        enc_ok = enc_ok && (cipher[i] == expected[i]);
    }

    aes_decrypt_block(cipher, key, decoded);
    bool dec_ok = true;
    for (int i = 0; i < 4; ++i) {
        dec_ok = dec_ok && (decoded[i] == plain[i]);
    }

    return enc_ok && dec_ok;
}

static bool runOptionalMemorySelfTest() {
    printDivider("OPTIONAL MEMORY SELF-TEST");

    if (!runAesKnownAnswerTest()) {
        std::cout << "[FAIL] AES-128 known-answer test failed.\n";
        return false;
    }
    std::cout << "[PASS] AES-128 known-answer test passed.\n";

    if (stackedMemory.isSecurityLocked()) {
        stackedMemory.clearSecurityLockdown();
    }

    stackedMemory.write(0, 900, 0x12345678u);
    stackedMemory.write(0, 901, 0xDEADBEEFu);

    const uint32_t a = stackedMemory.read(0, 900);
    const uint32_t b = stackedMemory.read(0, 901);
    if (a != 0x12345678u || b != 0xDEADBEEFu) {
        std::cout << "[FAIL] Basic memory read/write test failed.\n";
        return false;
    }

    std::cout << "[PASS] Basic memory read/write test passed.\n";
    return true;
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    std::string err;
    if (!parseOptions(argc, argv, opt, err)) {
        if (!err.empty()) {
            std::cerr << "[ERROR] " << err << '\n';
        }
        printUsage(argv[0]);
        return err.empty() ? 0 : 1;
    }

    printDivider("CRYPTO3D EXECUTION VALIDATION");
    std::cout << "[INFO] Input image: " << opt.image_path << '\n';

    std::vector<uint32_t> image;
    if (!loadHexImage(opt.image_path, image, err)) {
        std::cerr << "[ERROR] " << err << '\n';
        return 1;
    }
    std::cout << "[INFO] Loaded/padded image words: " << image.size() << '\n';

    ValidationContract contract = defaultContract();
    bool contract_loaded = false;

    if (opt.explicit_contract) {
        if (!loadContract(opt.contract_path, contract, err)) {
            std::cerr << "[ERROR] " << err << '\n';
            return 2;
        }
        contract_loaded = true;
    } else {
        std::ifstream probe("demo.contract");
        if (probe.good()) {
            probe.close();
            if (!loadContract("demo.contract", contract, err)) {
                std::cerr << "[ERROR] " << err << '\n';
                return 2;
            }
            opt.contract_path = "demo.contract";
            contract_loaded = true;
        }
    }

    if (contract_loaded) {
        std::cout << "[INFO] Contract: " << opt.contract_path << '\n';
    } else {
        std::cout << "[INFO] Contract: built-in demo defaults\n";
    }

    if (!runAesKnownAnswerTest()) {
        std::cerr << "[FAIL] AES-128 known-answer test failed.\n";
        return 3;
    }
    std::cout << "[PASS] AES-128 known-answer test passed.\n";

    // Load image once for pre-execution authentication and signature checks.
    loadImageIntoStackedMemory(image);

    if (contract.image_pre_validate) {
        const int rc = secure_validate_image(0);
        if (rc != 0) {
            std::cerr << "[FAIL] Pre-execution secure image validation failed with rc=" << rc << '\n';
            return 4;
        }
        std::cout << "[PASS] Pre-execution secure image validation passed.\n";
    }

    uint32_t signature_addr = 0u;
    bool has_functional_check = false;
    if (contract.signature_enabled) {
        if (!getSignatureAddress(contract, signature_addr, err)) {
            std::cerr << "[ERROR] " << err << '\n';
            return 5;
        }

        uint32_t signature_before = 0u;
        const int rc = secure_read_data_word_plain(signature_addr, &signature_before);
        if (rc != 0) {
            std::cerr << "[ERROR] Could not read pre-run plaintext signature word. rc=" << rc << '\n';
            return 5;
        }

        std::cout << "[INFO] Signature address: " << std::dec << signature_addr
                  << ", pre-run value=0x" << std::hex << std::uppercase
                  << std::setw(8) << std::setfill('0') << signature_before
                  << std::setfill(' ') << std::dec << '\n';

        if (contract.signature_pre_zero && signature_before != 0u) {
            std::cerr << "[FAIL] Signature precondition failed: expected zero before execution.\n";
            return 6;
        }

        has_functional_check = true;
    } else {
        std::cout << "[INFO] Signature checks disabled by contract.\n";
    }

    printDivider("CPU RUN");
    uint32_t top_status = 0u;
    Crypto3DStackCPU_top(image.data(), static_cast<uint32_t>(image.size()), &top_status);

    const uint32_t retired = (top_status >> 16) & 0xFFFFu;
    std::cout << "[INFO] Top status = 0x"
              << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
              << top_status << std::setfill(' ') << std::dec
              << " retired=" << retired << '\n';

    const uint32_t perf_cycles = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_CYCLES);
    const uint32_t perf_stalls = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_STALLS);
    const uint32_t perf_load_use = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_LOAD_USE_STALLS);
    const uint32_t perf_branches = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_BRANCH_PREDICTIONS);
    const uint32_t perf_misp = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_BRANCH_MISPREDICTS);
    const uint32_t perf_ih = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_ICACHE_HITS);
    const uint32_t perf_im = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_ICACHE_MISSES);
    const uint32_t perf_dh = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_DCACHE_HITS);
    const uint32_t perf_dm = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_DCACHE_MISSES);
    const uint32_t perf_fmem = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_FORWARD_MEM);
    const uint32_t perf_fwb = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_FORWARD_WB);
    const uint32_t perf_store_fwd = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_STORE_DATA_FORWARDS);
    const uint32_t perf_aes = Crypto3DStackCPU_get_perf_counter(CRYPTO3D_PERF_AES_INSTRUCTIONS);

    const uint32_t cpi_x100 = (retired == 0u) ? 0u : (perf_cycles * 100u) / retired;
    printDivider("ARCHITECTURAL PERFORMANCE COUNTERS");
    std::cout << "[INFO] cycles=" << perf_cycles
              << " retired=" << retired
              << " CPI=" << (cpi_x100 / 100u) << "." << std::setw(2) << std::setfill('0') << (cpi_x100 % 100u)
              << std::setfill(' ') << '\n';
    std::cout << "[INFO] stalls=" << perf_stalls
              << " load_use_stalls=" << perf_load_use
              << " forward_mem=" << perf_fmem
              << " forward_wb=" << perf_fwb
              << " store_data_forwards=" << perf_store_fwd << '\n';
    std::cout << "[INFO] branch_predictions=" << perf_branches
              << " branch_mispredicts=" << perf_misp
              << " aes_instructions=" << perf_aes << '\n';
    std::cout << "[INFO] icache_hits=" << perf_ih
              << " icache_misses=" << perf_im
              << " dcache_hits=" << perf_dh
              << " dcache_misses=" << perf_dm << '\n';

    bool execution_ok = true;

    if (contract.status_expect_clean && (top_status & (STATUS_SECURITY_LOCK | STATUS_KEY_FAILURE)) != 0u) {
        execution_ok = false;
        if ((top_status & STATUS_SECURITY_LOCK) != 0u) {
            std::cout << "[FAIL] Security-lock bit set in top status.\n";
        }
        if ((top_status & STATUS_KEY_FAILURE) != 0u) {
            std::cout << "[FAIL] Key-check failure bit set in top status.\n";
        }
    }

    if (retired < contract.status_min_retired) {
        execution_ok = false;
        std::cout << "[FAIL] Retired instruction count below minimum. expected>="
                  << contract.status_min_retired << " actual=" << retired << '\n';
    }

    if (contract.status_max_retired != 0u && retired > contract.status_max_retired) {
        execution_ok = false;
        std::cout << "[FAIL] Retired instruction count above maximum. expected<="
                  << contract.status_max_retired << " actual=" << retired << '\n';
    }

    if (execution_ok) {
        std::cout << "[PASS] Top status checks passed.\n";
    }

    if (contract.image_post_validate) {
        const int rc = secure_validate_image(0);
        if (rc != 0) {
            execution_ok = false;
            std::cout << "[FAIL] Post-execution secure image validation/reseal failed with rc=" << rc << '\n';
        } else {
            std::cout << "[PASS] Post-execution secure image validation/reseal passed.\n";
        }
    }

    printDivider("FUNCTIONAL CONTRACT");

    if (contract.signature_enabled) {
        uint32_t signature_after = 0u;
        const int rc = secure_read_data_word_plain(signature_addr, &signature_after);
        if (rc != 0) {
            execution_ok = false;
            std::cout << "[FAIL] Could not read post-run plaintext signature word. rc=" << rc << '\n';
        } else if (signature_after != contract.signature_expected) {
            execution_ok = false;
            std::cout << "[FAIL] Signature mismatch. expected=0x"
                      << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                      << contract.signature_expected << " actual=0x" << std::setw(8)
                      << signature_after << std::setfill(' ') << std::dec << '\n';
        } else {
            std::cout << "[PASS] Signature matches expected value 0x"
                      << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                      << contract.signature_expected << std::setfill(' ') << std::dec << '\n';
        }
    }

    bool any_reg_check = false;
    bool regs_ok = true;
    for (int i = 0; i < NUM_REGS; ++i) {
        if (!contract.reg_enabled[static_cast<size_t>(i)]) continue;
        any_reg_check = true;
        has_functional_check = true;

        const uint32_t expected = contract.reg_expected[static_cast<size_t>(i)];
        const uint32_t actual = reg_file[i];
        if (actual != expected) {
            regs_ok = false;
            std::cout << "[FAIL] reg[" << std::dec << i << "] mismatch. expected=0x"
                      << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                      << expected << " actual=0x" << std::setw(8) << actual
                      << std::setfill(' ') << std::dec << '\n';
        }
    }

    if (any_reg_check) {
        if (regs_ok) {
            std::cout << "[PASS] Register contract checks passed.\n";
        } else {
            execution_ok = false;
        }
    } else {
        std::cout << "[INFO] Register checks disabled by contract.\n";
    }

    if (!has_functional_check) {
        execution_ok = false;
        std::cout << "[FAIL] Contract configured zero functional checks.\n";
    }

    if (contract.output_reload_validate) {
        printDivider("OUTPUT IMAGE RELOAD VALIDATION");
        loadImageIntoStackedMemory(image);
        const int rc = secure_validate_image(0);
        if (rc != 0) {
            execution_ok = false;
            std::cout << "[FAIL] Reloaded output image validation failed with rc=" << rc << '\n';
        } else {
            std::cout << "[PASS] Reloaded output image validation passed.\n";
        }
    }

    if (!opt.output_image_path.empty()) {
        if (!writeHexImage(opt.output_image_path, image, err)) {
            std::cerr << "[ERROR] " << err << '\n';
            return 7;
        }
        std::cout << "[INFO] Wrote post-execution image: " << opt.output_image_path << '\n';
    }

    if (opt.verbose || opt.dump_memory) {
        printDivider("REGISTER FILE DUMP");
        dumpRegisters();
    }

    if (opt.dump_memory) {
        printDivider("MEMORY DUMP: HEADER WORDS");
        dumpMemory(0, SEC_HDR_WORDS);

        printDivider("MEMORY DUMP: FIRST DATA/TEXT WINDOW");
        dumpMemory(SEC_HDR_WORDS, 64);
    }

    if (!execution_ok) {
        std::cerr << "[FAIL] Crypto3D execution validation failed.\n";
        return 8;
    }

    std::cout << "\n[ALL TESTS PASSED] Functional execution, security status, and reseal validation passed.\n";

    if (opt.run_memory_self_test && !runOptionalMemorySelfTest()) {
        return 9;
    }

    return 0;
}
