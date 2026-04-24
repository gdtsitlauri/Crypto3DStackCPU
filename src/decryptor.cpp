#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "3d.h"
#include "header.h"

extern StackedMemory3D stackedMemory;

namespace {

constexpr uint32_t kTargetLayer = 0u;
constexpr uint32_t kWordsPerBlock = INSTRS_PER_BLOCK;
constexpr uint32_t kMaxWords = MEM_SIZE;

struct Options {
    std::string input_image;
    std::string output_text;
    std::string compare_text;
    std::string output_data;
    bool verbose = false;
};

static void secure_zero_words(uint32_t* ptr, size_t count) {
    volatile uint32_t* vptr = ptr;
    for (size_t i = 0; i < count; ++i) {
        vptr[i] = 0u;
    }
}

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

static std::string strip_comment(const std::string& line) {
    const size_t hash = line.find('#');
    if (hash == std::string::npos) return line;
    return line.substr(0, hash);
}

static bool parse_hex_word(const std::string& token, uint32_t& out) {
    std::string t = trim(token);
    if (t.empty()) return false;

    if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
        t = t.substr(2);
    }

    if (t.empty() || t.size() > 8) return false;
    for (char c : t) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }

    try {
        size_t idx = 0;
        unsigned long parsed = std::stoul(t, &idx, 16);
        if (idx != t.size()) return false;
        out = static_cast<uint32_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

static bool load_hex_words(const std::string& path,
                           std::vector<uint32_t>& words,
                           std::string& err,
                           uint32_t max_words = kMaxWords) {
    std::ifstream fin(path);
    if (!fin) {
        err = "Cannot open file: " + path;
        return false;
    }

    words.clear();
    std::string line;
    uint32_t line_no = 0;
    while (std::getline(fin, line)) {
        ++line_no;
        const std::string clean = trim(strip_comment(line));
        if (clean.empty()) continue;

        uint32_t value = 0u;
        if (!parse_hex_word(clean, value)) {
            err = "Invalid hex word at " + path + ":" + std::to_string(line_no) + " -> '" + clean + "'";
            return false;
        }

        if (words.size() >= max_words) {
            err = "File exceeds maximum supported image size of " + std::to_string(max_words) + " words: " + path;
            return false;
        }

        words.push_back(value);
    }

    if (words.empty()) {
        err = "File contains no hex words: " + path;
        return false;
    }

    return true;
}

static bool write_hex_words(const std::string& path,
                            const std::vector<uint32_t>& words,
                            std::string& err) {
    std::ofstream fout(path);
    if (!fout) {
        err = "Cannot open output file: " + path;
        return false;
    }

    for (uint32_t word : words) {
        fout << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << word << '\n';
    }

    return true;
}

static void reset_and_load_image(const std::vector<uint32_t>& image) {
    if (stackedMemory.isSecurityLocked()) {
        stackedMemory.clearSecurityLockdown();
    }

    for (uint32_t i = 0; i < kMaxWords; ++i) {
        stackedMemory.write(kTargetLayer, i, 0u);
    }

    for (uint32_t i = 0; i < image.size() && i < kMaxWords; ++i) {
        stackedMemory.write(kTargetLayer, i, image[i]);
    }

    invalidateCaches();
}

static bool read_and_validate_metadata(uint32_t& text_start,
                                       uint32_t& text_words,
                                       uint32_t& text_end,
                                       uint32_t& epoch,
                                       uint32_t& data_start,
                                       uint32_t& data_words,
                                       uint32_t& data_end,
                                       uint32_t& data_flags,
                                       std::string& err) {
    if (secure_get_image_region(&text_start, &text_words, &text_end, &epoch) != 0) {
        err = "Could not read secure text metadata";
        return false;
    }

    if (secure_get_data_region(&data_start, &data_words, &data_end, &data_flags) != 0) {
        err = "Could not read secure data metadata";
        return false;
    }

    if (text_start < SEC_TEXT_START_WORD || text_start > kMaxWords) {
        err = "Invalid text_start in secure header";
        return false;
    }
    if (text_end < text_start || text_end > kMaxWords) {
        err = "Invalid text_end in secure header";
        return false;
    }
    if (text_words > (text_end - text_start)) {
        err = "Invalid text_words in secure header";
        return false;
    }
    if ((text_start % kWordsPerBlock) != 0u || (text_end % kWordsPerBlock) != 0u) {
        err = "Text region is not AES-block aligned";
        return false;
    }
    if (epoch == 0u) {
        err = "Invalid zero epoch in secure header";
        return false;
    }

    if (data_start < text_end || data_start > kMaxWords) {
        err = "Invalid data_start in secure header";
        return false;
    }
    if (data_end < data_start || data_end > kMaxWords) {
        err = "Invalid data_end in secure header";
        return false;
    }
    if (data_words > (data_end - data_start)) {
        err = "Invalid data_words in secure header";
        return false;
    }
    if ((data_start % kWordsPerBlock) != 0u || (data_end % kWordsPerBlock) != 0u) {
        err = "Data region is not AES-block aligned";
        return false;
    }

    return true;
}

static bool decrypt_text_region(const uint32_t app_key[4],
                                uint32_t text_start,
                                uint32_t text_words,
                                uint32_t text_end,
                                std::vector<uint32_t>& plain_text,
                                std::string& err) {
    plain_text.assign(text_words, 0u);

    const uint32_t start_block = text_start / kWordsPerBlock;
    const uint32_t end_block = text_end / kWordsPerBlock;
    const uint32_t text_plain_end = text_start + text_words;

    for (uint32_t logical_block = start_block; logical_block < end_block; ++logical_block) {
        const uint32_t phys_block = secure_map_text_block(logical_block);
        const uint32_t phys_addr = phys_block * kWordsPerBlock;

        if (phys_block >= (kMaxWords / kWordsPerBlock) || phys_addr + kWordsPerBlock > kMaxWords) {
            err = "Invalid mapped physical text block during decryption";
            return false;
        }

        uint32_t cipher[4] = {0u, 0u, 0u, 0u};
        uint32_t plain[4] = {0u, 0u, 0u, 0u};

        for (uint32_t i = 0; i < kWordsPerBlock; ++i) {
            cipher[i] = stackedMemory.rawRead(kTargetLayer, phys_addr + i);
        }

        aes_decrypt_block(cipher, const_cast<uint32_t*>(app_key), plain);

        const uint32_t logical_addr = logical_block * kWordsPerBlock;
        for (uint32_t i = 0; i < kWordsPerBlock; ++i) {
            const uint32_t word_addr = logical_addr + i;
            if (word_addr >= text_start && word_addr < text_plain_end) {
                plain_text[word_addr - text_start] = plain[i];
            }
        }

        secure_zero_words(cipher, 4);
        secure_zero_words(plain, 4);
    }

    return true;
}

static bool dump_data_region_plain(uint32_t data_start,
                                   uint32_t data_words,
                                   std::vector<uint32_t>& plain_data,
                                   std::string& err) {
    plain_data.assign(data_words, 0u);

    for (uint32_t i = 0; i < data_words; ++i) {
        uint32_t value = 0u;
        const int rc = secure_read_data_word_plain(data_start + i, &value);
        if (rc != 0) {
            err = "Could not read plaintext data word at image word " + std::to_string(data_start + i) +
                  " (rc=" + std::to_string(rc) + ")";
            return false;
        }
        plain_data[i] = value;
    }

    return true;
}

static bool compare_with_reference(const std::vector<uint32_t>& got,
                                   const std::string& reference_path,
                                   std::string& err,
                                   bool verbose) {
    std::vector<uint32_t> ref;
    if (!load_hex_words(reference_path, ref, err, 0xFFFFFFFFu)) {
        return false;
    }

    size_t mismatches = 0;
    const size_t max_len = std::max(got.size(), ref.size());
    for (size_t i = 0; i < max_len; ++i) {
        const bool got_valid = i < got.size();
        const bool ref_valid = i < ref.size();
        const uint32_t got_word = got_valid ? got[i] : 0u;
        const uint32_t ref_word = ref_valid ? ref[i] : 0u;

        if (!got_valid || !ref_valid || got_word != ref_word) {
            ++mismatches;
            if (verbose && mismatches <= 16u) {
                std::cout << "[MISMATCH] word " << std::dec << i
                          << " expected=";
                if (ref_valid) {
                    std::cout << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << ref_word;
                } else {
                    std::cout << "<missing>";
                }
                std::cout << " actual=";
                if (got_valid) {
                    std::cout << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << got_word;
                } else {
                    std::cout << "<missing>";
                }
                std::cout << std::dec << std::nouppercase << '\n';
            }
        }
    }

    if (mismatches != 0u) {
        err = "Reference compare failed: " + std::to_string(mismatches) + " mismatch(es)";
        return false;
    }

    return true;
}

static void print_usage(const char* argv0) {
    std::cerr
        << "Usage:\n"
        << "  " << argv0 << " encrypted.hex output_text.hex [options]\n"
        << "  " << argv0 << " encrypted.hex reference_text.hex output_text.hex [options]\n\n"
        << "Options:\n"
        << "  --compare <reference_text.hex>   Compare decrypted text with reference.\n"
        << "  --data-output <plain_data.hex>   Also write plaintext data words.\n"
        << "  --verbose                        Print non-secret metadata and compare details.\n"
        << "  --help                           Show this help.\n\n"
        << "Notes:\n"
        << "  The application key is never printed.\n"
        << "  The input image must pass secure header/tag validation before decryption.\n";
}

static bool parse_options(int argc, char** argv, Options& opt, std::string& err) {
    std::vector<std::string> positional;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            std::exit(0);
        }

        if (arg == "--verbose" || arg == "-v") {
            opt.verbose = true;
            continue;
        }

        if (arg == "--compare") {
            if (i + 1 >= argc) {
                err = "--compare requires a path";
                return false;
            }
            opt.compare_text = argv[++i];
            continue;
        }

        if (arg == "--data-output") {
            if (i + 1 >= argc) {
                err = "--data-output requires a path";
                return false;
            }
            opt.output_data = argv[++i];
            continue;
        }

        if (!arg.empty() && arg[0] == '-') {
            // Backward-compatible positional '-' means no reference file only
            // when it appears as the second positional argument.
            if (arg != "-") {
                err = "Unknown option: " + arg;
                return false;
            }
        }

        positional.push_back(arg);
    }

    if (positional.size() == 2u) {
        opt.input_image = positional[0];
        opt.output_text = positional[1];
    } else if (positional.size() == 3u) {
        opt.input_image = positional[0];
        if (positional[1] != "-") {
            if (!opt.compare_text.empty() && opt.compare_text != positional[1]) {
                err = "Reference provided both positionally and with --compare";
                return false;
            }
            opt.compare_text = positional[1];
        }
        opt.output_text = positional[2];
    } else {
        err = "Invalid number of positional arguments";
        return false;
    }

    if (opt.input_image.empty() || opt.output_text.empty()) {
        err = "Missing input or output path";
        return false;
    }

    return true;
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    std::string err;

    if (!parse_options(argc, argv, opt, err)) {
        std::cerr << "[ERROR] " << err << "\n";
        print_usage(argv[0]);
        return 1;
    }

    std::vector<uint32_t> image;
    if (!load_hex_words(opt.input_image, image, err, kMaxWords)) {
        std::cerr << "[ERROR] " << err << "\n";
        return 2;
    }

    reset_and_load_image(image);

    const int validate_rc = secure_validate_image(kTargetLayer);
    if (validate_rc != 0 || stackedMemory.isSecurityLocked()) {
        std::cerr << "[ERROR] Secure image validation failed; refusing to decrypt (rc="
                  << validate_rc << ").\n";
        return 3;
    }

    uint32_t app_key[4] = {0u, 0u, 0u, 0u};
    const int key_rc = extract_key_from_large_block(kTargetLayer, app_key);
    if (key_rc != 0 || stackedMemory.isSecurityLocked()) {
        secure_zero_words(app_key, 4);
        std::cerr << "[ERROR] Secure app-key unwrap failed (rc=" << key_rc << ").\n";
        return 4;
    }

    uint32_t text_start = 0u;
    uint32_t text_words = 0u;
    uint32_t text_end = 0u;
    uint32_t epoch = 0u;
    uint32_t data_start = 0u;
    uint32_t data_words = 0u;
    uint32_t data_end = 0u;
    uint32_t data_flags = 0u;

    if (!read_and_validate_metadata(text_start, text_words, text_end, epoch,
                                    data_start, data_words, data_end, data_flags, err)) {
        secure_zero_words(app_key, 4);
        std::cerr << "[ERROR] " << err << "\n";
        return 5;
    }

    if (opt.verbose) {
        std::cout << "[INFO] Secure image validation passed.\n";
        std::cout << "[INFO] Text region: start=" << std::dec << text_start
                  << " words=" << text_words
                  << " enc_end=" << text_end
                  << " epoch=" << epoch << "\n";
        std::cout << "[INFO] Data region: start=" << data_start
                  << " words=" << data_words
                  << " enc_end=" << data_end
                  << " flags=0x" << std::hex << std::uppercase << data_flags
                  << std::dec << std::nouppercase << "\n";
    }

    std::vector<uint32_t> plain_text;
    if (!decrypt_text_region(app_key, text_start, text_words, text_end, plain_text, err)) {
        secure_zero_words(app_key, 4);
        std::cerr << "[ERROR] " << err << "\n";
        return 6;
    }

    secure_zero_words(app_key, 4);

    if (!write_hex_words(opt.output_text, plain_text, err)) {
        std::cerr << "[ERROR] " << err << "\n";
        return 7;
    }

    std::cout << "[OK] Decrypted text written to " << opt.output_text
              << " (" << std::dec << plain_text.size() << " words).\n";

    if (!opt.compare_text.empty()) {
        if (!compare_with_reference(plain_text, opt.compare_text, err, opt.verbose)) {
            std::cerr << "[ERROR] " << err << "\n";
            return 8;
        }
        std::cout << "[OK] Decrypted text matches reference: " << opt.compare_text << "\n";
    }

    if (!opt.output_data.empty()) {
        std::vector<uint32_t> plain_data;
        if (!dump_data_region_plain(data_start, data_words, plain_data, err)) {
            std::cerr << "[ERROR] " << err << "\n";
            return 9;
        }
        if (!write_hex_words(opt.output_data, plain_data, err)) {
            std::cerr << "[ERROR] " << err << "\n";
            return 10;
        }
        std::cout << "[OK] Plain data written to " << opt.output_data
                  << " (" << std::dec << plain_data.size() << " words).\n";
    }

    return 0;
}
