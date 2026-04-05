#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <cctype>
#include <sstream>
#include "3d.h"
#include "header.h"

// Top function exposed for HLS simulation/integration.
extern "C" void Crypto3DStackCPU_top(volatile uint32_t* image,
                                      uint32_t word_count,
                                      volatile uint32_t* status_word);

// Globals provided by 3d.cpp.
extern StackedMemory3D stackedMemory;
extern uint32_t reg_file[NUM_REGS];

#define EXPECTED_SIGNATURE 0x000000AE
#define DEMO_SIGNATURE_DATA_OFFSET 0

struct ValidationContract {
    bool signature_enabled = true;
    bool signature_pre_zero = true;
    uint32_t signature_offset = DEMO_SIGNATURE_DATA_OFFSET;
    uint32_t signature_expected = EXPECTED_SIGNATURE;
    std::array<bool, NUM_REGS> reg_enabled{};
    std::array<uint32_t, NUM_REGS> reg_expected{};
};

static std::string trim(const std::string &s) {
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

static bool parseBool(const std::string &token, bool &value) {
    std::string t = toLower(trim(token));
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

static bool parseU32(const std::string &token, uint32_t &value) {
    try {
        size_t idx = 0;
        unsigned long parsed = std::stoul(trim(token), &idx, 0);
        if (idx != trim(token).size()) return false;
        value = static_cast<uint32_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

static ValidationContract defaultContract() {
    ValidationContract c;
    c.reg_enabled.fill(false);
    c.reg_expected.fill(0u);
    c.reg_enabled[2] = true; c.reg_expected[2] = 0x00000001u;
    c.reg_enabled[3] = true; c.reg_expected[3] = 0x00000002u;
    c.reg_enabled[4] = true; c.reg_expected[4] = 0x00000003u;
    c.reg_enabled[5] = true; c.reg_expected[5] = 0x00000004u;
    c.reg_enabled[6] = true; c.reg_expected[6] = 0x00000005u;
    c.reg_enabled[7] = true; c.reg_expected[7] = 0x00000006u;
    c.reg_enabled[8] = true; c.reg_expected[8] = EXPECTED_SIGNATURE;
    c.reg_enabled[11] = true; c.reg_expected[11] = 0x00000005u;
    return c;
}

static bool loadContract(const std::string &path, ValidationContract &contract, std::string &err) {
    std::ifstream fin(path);
    if (!fin) {
        err = "Cannot open contract file: " + path;
        return false;
    }

    std::string line;
    int line_no = 0;
    while (std::getline(fin, line)) {
        ++line_no;
        size_t hash = line.find('#');
        if (hash != std::string::npos) {
            line = line.substr(0, hash);
        }

        line = trim(line);
        if (line.empty()) continue;

        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            err = "Contract line " + std::to_string(line_no) + ": missing '='";
            return false;
        }

        std::string key = toLower(trim(line.substr(0, eq)));
        std::string value = trim(line.substr(eq + 1));

        if (key == "signature.enabled") {
            bool flag = false;
            if (!parseBool(value, flag)) {
                err = "Contract line " + std::to_string(line_no) + ": invalid bool for signature.enabled";
                return false;
            }
            contract.signature_enabled = flag;
            continue;
        }

        if (key == "signature.pre_zero") {
            bool flag = false;
            if (!parseBool(value, flag)) {
                err = "Contract line " + std::to_string(line_no) + ": invalid bool for signature.pre_zero";
                return false;
            }
            contract.signature_pre_zero = flag;
            continue;
        }

        if (key == "signature.offset") {
            uint32_t parsed = 0u;
            if (!parseU32(value, parsed)) {
                err = "Contract line " + std::to_string(line_no) + ": invalid value for signature.offset";
                return false;
            }
            contract.signature_offset = parsed;
            continue;
        }

        if (key == "signature.expected") {
            uint32_t parsed = 0u;
            if (!parseU32(value, parsed)) {
                err = "Contract line " + std::to_string(line_no) + ": invalid value for signature.expected";
                return false;
            }
            contract.signature_expected = parsed;
            continue;
        }

        if (key == "registers.enabled" || key == "regs.enabled") {
            bool flag = false;
            if (!parseBool(value, flag)) {
                err = "Contract line " + std::to_string(line_no) + ": invalid bool for registers.enabled";
                return false;
            }
            if (!flag) {
                contract.reg_enabled.fill(false);
            }
            continue;
        }

        if (key.rfind("reg.", 0) == 0) {
            std::string idx_token = key.substr(4);
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

            contract.reg_enabled[(size_t)reg_idx] = true;
            contract.reg_expected[(size_t)reg_idx] = parsed;
            continue;
        }

        err = "Contract line " + std::to_string(line_no) + ": unknown key '" + key + "'";
        return false;
    }

    return true;
}

void printDivider(const std::string& title) {
    std::cout << "\n================ " << title << " ================\n";
}

void dumpLayer(size_t layer, size_t words = 16, size_t offset = 0) {
    std::cout << "Dump layer " << layer << " (words "
              << std::dec
              << offset << "-" << (offset + words - 1) << "):\n";
    for (size_t i = 0; i < words; i++) {
        std::cout << "L" << layer << "[" << std::setw(3) << (offset + i) << "] = 0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << stackedMemory.read(layer, offset + i) << std::endl;
    }
    std::cout << std::dec;
}

int main(int argc, char **argv) {
    // =============================================================
    // [PROGRAM EXECUTION TEST] - runs demo.hex from this folder
    // =============================================================
    printDivider("PROGRAM EXECUTION TEST");

    // --- LOAD HEX FILE ---
    std::string hex_file = (argc > 1) ? argv[1] : "demo.hex";
    std::cout << "[INFO] Using input file: " << hex_file << std::endl;

    std::ifstream fin(hex_file);
    if (!fin) {
        std::cerr << "[ERROR] Cannot open file: " << hex_file << std::endl;
        return 1;
    }

    std::vector<uint32_t> program;
    std::string line;
    while (std::getline(fin, line)) {
        if (line.empty()) continue;
        try {
            uint32_t word = std::stoul(line, nullptr, 16);
            program.push_back(word);
        } catch (...) {
            std::cerr << "[ERROR] Invalid hex line: " << line << std::endl;
            return 1;
        }
    }
    fin.close();
    std::cout << "[INFO] Loaded " << program.size()
              << " words from file into program buffer." << std::endl;

    ValidationContract contract = defaultContract();
    std::string contract_file = (argc > 2) ? argv[2] : "demo.contract";
    bool contract_loaded = false;
    {
        std::ifstream probe(contract_file);
        if (probe.good()) {
            probe.close();
            std::string contract_err;
            if (!loadContract(contract_file, contract, contract_err)) {
                std::cerr << "[ERROR] " << contract_err << std::endl;
                return 1;
            }
            contract_loaded = true;
        } else if (argc > 2) {
            std::cerr << "[ERROR] Cannot open explicit contract file: " << contract_file << std::endl;
            return 1;
        }
    }

    if (contract_loaded) {
        std::cout << "[INFO] Loaded validation contract: " << contract_file << std::endl;
    } else {
        std::cout << "[INFO] Contract file not provided/found. Using built-in demo contract." << std::endl;
    }

    // Fill memory (single layer: protectedWrite for 0-31, write for 32+)
    for (size_t i = 0; i < program.size() && i < MEM_SIZE; i++) {
        if (i < 32)
            stackedMemory.protectedWrite(0, i, program[i]);
        else
            stackedMemory.write(0, i, program[i]);
    }

    uint32_t data_start = stackedMemory.protectedRead(0, SEC_HDR_W_DATA_START);
    uint32_t signature_addr = 0u;

    if (contract.signature_enabled) {
        signature_addr = data_start + contract.signature_offset;
        if (signature_addr >= MEM_SIZE) {
            std::cerr << "[ERROR] Computed signature address out of range: "
                      << std::dec << signature_addr << std::endl;
            return 1;
        }

        std::cout << "[INFO] Computed signature address from header: "
                  << std::dec << signature_addr
                  << " (data_start=" << data_start
                  << ", data_offset=" << contract.signature_offset << ")"
                  << std::endl;
    } else {
        std::cout << "[INFO] Signature checks disabled by contract." << std::endl;
    }

    dumpLayer(0, 16, 0);
    // --- DEBUG: Dump full block 0 (words 0-31) layer 0 before simulation ---
    std::cout << "[DEBUG] Block 0 dump (layer 0, words 0-31) before simulation:" << std::endl;
    for (size_t i = 0; i < 32; i++) {
        std::cout << "L0[" << std::setw(2) << i << "] = 0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << stackedMemory.protectedRead(0, i) << std::endl;
    }

    bool execution_ok = true;
    bool has_functional_check = false;

    uint32_t signature_before = 0;
    if (contract.signature_enabled) {
        has_functional_check = true;
        if (secure_read_data_word_plain(signature_addr, &signature_before) != 0) {
            std::cerr << "[ERROR] Could not read plaintext pre-run signature word." << std::endl;
            return 2;
        }
        std::cout << "[INFO] Pre-run signature @ " << std::dec << signature_addr
                  << " = 0x" << std::hex << std::uppercase
                  << std::setw(8) << std::setfill('0') << signature_before << std::endl;

        if (contract.signature_pre_zero && signature_before != 0) {
            std::cout << "[FAIL] Precondition failed: signature address is not zero before execution."
                      << std::endl;
            return 2;
        }
    }

    // --- RUN CPU ---
    std::cout << "[INFO] Starting Crypto3DStackCPU_top()..." << std::endl;
    uint32_t top_status = 0;
    Crypto3DStackCPU_top(program.data(), static_cast<uint32_t>(program.size()), &top_status);
    std::cout << "[INFO] Crypto3DStackCPU execution complete." << std::endl;
    std::cout << "[INFO] Top status word = 0x"
              << std::hex << std::uppercase
              << std::setw(8) << std::setfill('0') << top_status
              << std::dec << std::nouppercase << std::endl;

    // --- DEBUG: Dump full block 0 (words 0-31) layer 0 after simulation ---
    std::cout << "[DEBUG] Block 0 dump (layer 0, words 0-31) after simulation:" << std::endl;
    for (size_t i = 0; i < 32; i++) {
        std::cout << "L0[" << std::setw(2) << i << "] = 0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << stackedMemory.protectedRead(0, i) << std::endl;
    }

    if ((top_status & 0x3u) != 0u) {
        execution_ok = false;
        if ((top_status & 0x1u) != 0u) {
            std::cout << "[FAIL] Security lock bit set in top status." << std::endl;
        }
        if ((top_status & 0x2u) != 0u) {
            std::cout << "[FAIL] Key-check failure bit set in top status." << std::endl;
        }
    }

    printDivider("SIGNATURE CHECK");
    if (contract.signature_enabled) {
        uint32_t signature = 0;
        if (secure_read_data_word_plain(signature_addr, &signature) != 0) {
            std::cerr << "[ERROR] Could not read plaintext post-run signature word." << std::endl;
            return 3;
        }
        std::cout << "Signature @ expected address " << std::dec << signature_addr
                  << " = 0x" << std::hex << std::uppercase
                  << std::setw(8) << std::setfill('0') << signature << std::endl;

        if (signature == contract.signature_expected) {
            std::cout << "[OK] SUCCESS: Signature matches expected value 0x"
                      << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                      << contract.signature_expected << std::dec << std::nouppercase << std::endl;
        } else {
            execution_ok = false;
            std::cout << "[FAIL] Signature mismatch. expected=0x"
                      << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                      << contract.signature_expected << " actual=0x"
                      << std::setw(8) << signature << std::dec << std::nouppercase << std::endl;

            size_t start = (program.size() > 0x80) ? 0x80 : 0;
            size_t end   = (program.size() > 0xA0) ? 0xA0 : program.size();
            std::cout << "\n[DEBUG] Dumping possible signature area ("
                      << std::dec << start << "-" << end << "):\n";
            for (size_t i = start; i <= end; i++) {
                uint32_t val = stackedMemory.protectedRead(0, i);
                std::cout << "L0[" << std::setw(3) << i << "] = 0x"
                          << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                          << val << std::endl;
            }
        }
    } else {
        std::cout << "[INFO] Signature checks skipped by contract." << std::endl;
    }

    printDivider("EXECUTION PROOF");
    bool regs_ok = true;
    bool any_reg_check = false;
    for (int i = 0; i < NUM_REGS; ++i) {
        if (!contract.reg_enabled[(size_t)i]) continue;
        any_reg_check = true;
        has_functional_check = true;
        if (reg_file[i] != contract.reg_expected[(size_t)i]) {
            regs_ok = false;
            std::cout << "[FAIL] reg[" << i << "] mismatch. expected=0x"
                      << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                      << contract.reg_expected[(size_t)i]
                      << " actual=0x" << std::setw(8) << reg_file[i]
                      << std::dec << std::nouppercase << std::endl;
        }
    }

    if (any_reg_check) {
        if (regs_ok) {
            std::cout << "[OK] Register proof passed (contract checks)." << std::endl;
        } else {
            execution_ok = false;
            std::cout << "[FAIL] Register proof failed." << std::endl;
        }
    } else {
        std::cout << "[INFO] Register checks skipped by contract." << std::endl;
    }

    if (!has_functional_check) {
        execution_ok = false;
        std::cout << "[FAIL] Contract configured zero functional checks." << std::endl;
    }

    if (!execution_ok) {
        std::cerr << "[FAIL] ASM execution proof failed." << std::endl;
        return 3;
    }

    std::cout << "[OK] Functional contract checks passed." << std::endl;

    // --- DUMP REGISTERS ---
    printDivider("REGISTER FILE DUMP");
    for (int i = 0; i < NUM_REGS; i++) {
        std::cout << "reg[" << std::setw(2) << i << "] = 0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << reg_file[i] << std::endl;
    }

    // --- DUMP MEMORY (layer 0, first 64 words) ---
    printDivider("MEMORY DUMP (layer 0, first 64 words)");
    dumpLayer(0, 64, 0);

    // --- DUMP LAST 32 WORDS ---
    printDivider("MEMORY DUMP (layer 0, last 32 words)");
    if (program.size() > 32) {
        dumpLayer(0, 32, program.size() - 32);
    }

    // =============================================================
    // [MEMORY FEATURE TESTS] - targeted 3D memory feature checks
    // =============================================================
    printDivider("MEMORY FEATURE TESTS");

    // --- INIT ---
    stackedMemory.addLayers(1); // single-layer policy
    std::cout << std::dec << "Layers: " << stackedMemory.getNumLayers()
              << ", Words/layer: " << stackedMemory.getNumWords() << std::endl;

    // --- BASIC WRITE/READ ---
    printDivider("WRITE/READ");
    stackedMemory.write(0, 0, 0x12345678);
    stackedMemory.write(0, 1, 0xDEADBEEF);
    dumpLayer(0, 4, 0);

    // --- SCRAMBLE/UNSCRAMBLE ---
    printDivider("SCRAMBLE");
    stackedMemory.scrambleLayerWithKey(0, 0xA5A5A5A5);
    dumpLayer(0, 4, 0);
    stackedMemory.unscrambleLayerWithKey(0, 0xA5A5A5A5);
    dumpLayer(0, 4, 0);

    // --- AES ENCRYPT/DECRYPT ---
    printDivider("AES ENCRYPT/DECRYPT");
    stackedMemory.encryptLayer(0);
    dumpLayer(0, 4, 0);
    stackedMemory.decryptLayer(0);
    dumpLayer(0, 4, 0);

    // --- HW OBFUSCATION ---
    printDivider("HW OBFUSCATION");
    stackedMemory.hardwareObfuscate();
    dumpLayer(0, 4, 0);
    stackedMemory.hardwareObfuscate(); // apply again to restore original values
    dumpLayer(0, 4, 0);

    // --- ANTI-TAMPER ---
    printDivider("ANTI-TAMPER");
    stackedMemory.checkTamper(0, 0, 0x12345678); // correct expected value -> no reset
    std::cout << stackedMemory.getTamperStatus() << std::endl;
    stackedMemory.checkTamper(0, 0, 0x11111111); // wrong expected value -> reset
    std::cout << stackedMemory.getTamperStatus() << std::endl;
    dumpLayer(0, 4, 0);

    // --- KEY HIDE/EXTRACT ---
    printDivider("KEY HIDE/EXTRACT");
    size_t secret_bits[128];
    for (size_t i = 0; i < 128; i++) secret_bits[i] = i;
    uint32_t key_in[4] = {0xCAFEBABE, 0xAABBCCDD, 0x11223344, 0x55667788};
    uint32_t key_out[4] = {0, 0, 0, 0};
    stackedMemory.hideKeyInLayer(0, key_in, 4, secret_bits, 128);
    stackedMemory.extractKeyFromLayer(0, secret_bits, 128, key_out, 4);
    dumpLayer(0, 8, 0);
    std::cout << "Key in[0] = 0x" << std::hex << key_in[0]
              << " extracted[0] = 0x" << key_out[0] << std::endl;

    // --- PROCESSING LAYER ---
    printDivider("PROCESSING LAYER");
    stackedMemory.enableProcessingLayer(0);
    stackedMemory.write(0, 0, 0x1234);
    stackedMemory.protectedWrite(0, 1, 0x5678);
    uint32_t val = stackedMemory.protectedRead(0, 1);
    dumpLayer(0, 4, 0);
    std::cout << "Protected read L0[1] = 0x" << std::hex << val << std::endl;
    std::cout << stackedMemory.getProcessingLayerStatus() << std::endl;
    stackedMemory.clearProcessingLayer();

    return 0;
}
