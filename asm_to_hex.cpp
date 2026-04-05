#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr uint32_t kDataBase = 0x10010000u;
constexpr uint32_t kTextBase = 0x00400000u;

enum class Section {
    None,
    Data,
    Text,
};

struct Statement {
    Section section = Section::None;
    bool is_directive = false;
    uint32_t address = 0;
    int line_no = 0;
    std::string op;
    std::vector<std::string> args;
};

static std::string trim(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        start++;
    }

    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        end--;
    }

    return s.substr(start, end - start);
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static std::string strip_comment(const std::string &line) {
    size_t pos = line.find('#');
    if (pos == std::string::npos) return line;
    return line.substr(0, pos);
}

static bool is_identifier(const std::string &s) {
    if (s.empty()) return false;

    auto valid_first = [](char c) {
        return std::isalpha(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '$';
    };
    auto valid_next = [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '$';
    };

    if (!valid_first(s[0])) return false;
    for (size_t i = 1; i < s.size(); ++i) {
        if (!valid_next(s[i])) return false;
    }

    return true;
}

static std::vector<std::string> split_args(const std::string &arg_string) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : arg_string) {
        if (c == ',') {
            std::string token = trim(cur);
            if (!token.empty()) out.push_back(token);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }

    std::string token = trim(cur);
    if (!token.empty()) out.push_back(token);
    return out;
}

static bool parse_int64(const std::string &token, int64_t &out) {
    try {
        size_t idx = 0;
        out = std::stoll(token, &idx, 0);
        return idx == token.size();
    } catch (...) {
        return false;
    }
}

static bool parse_u32(const std::string &token,
                      const std::unordered_map<std::string, uint32_t> &symbols,
                      uint32_t &out) {
    auto it = symbols.find(token);
    if (it != symbols.end()) {
        out = it->second;
        return true;
    }

    int64_t v = 0;
    if (!parse_int64(token, v)) return false;
    out = static_cast<uint32_t>(v);
    return true;
}

static bool parse_reg(const std::string &token, uint32_t &reg) {
    static const std::unordered_map<std::string, uint32_t> kRegNames = {
        {"zero", 0}, {"at", 1},
        {"v0", 2}, {"v1", 3},
        {"a0", 4}, {"a1", 5}, {"a2", 6}, {"a3", 7},
        {"t0", 8}, {"t1", 9}, {"t2", 10}, {"t3", 11},
        {"t4", 12}, {"t5", 13}, {"t6", 14}, {"t7", 15},
        {"s0", 16}, {"s1", 17}, {"s2", 18}, {"s3", 19},
        {"s4", 20}, {"s5", 21}, {"s6", 22}, {"s7", 23},
        {"t8", 24}, {"t9", 25},
        {"k0", 26}, {"k1", 27},
        {"gp", 28}, {"sp", 29}, {"fp", 30}, {"ra", 31},
    };

    if (token.empty() || token[0] != '$') return false;
    std::string body = to_lower(token.substr(1));
    if (body.empty()) return false;

    bool is_number = true;
    for (char c : body) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            is_number = false;
            break;
        }
    }

    if (is_number) {
        int64_t n = 0;
        if (!parse_int64(body, n)) return false;
        if (n < 0 || n > 31) return false;
        reg = static_cast<uint32_t>(n);
        return true;
    }

    auto it = kRegNames.find(body);
    if (it == kRegNames.end()) return false;
    reg = it->second;
    return true;
}

static bool parse_mem_operand(const std::string &expr,
                              int32_t &offset,
                              uint32_t &base_reg,
                              std::string &err) {
    size_t l = expr.find('(');
    size_t r = expr.find(')');
    if (l == std::string::npos || r == std::string::npos || l >= r) {
        err = "Invalid memory operand: " + expr;
        return false;
    }

    std::string off_str = trim(expr.substr(0, l));
    std::string reg_str = trim(expr.substr(l + 1, r - l - 1));

    if (off_str.empty()) off_str = "0";

    int64_t off64 = 0;
    if (!parse_int64(off_str, off64)) {
        err = "Invalid memory offset: " + off_str;
        return false;
    }
    if (off64 < -32768 || off64 > 32767) {
        err = "Memory offset out of 16-bit range: " + off_str;
        return false;
    }

    if (!parse_reg(reg_str, base_reg)) {
        err = "Invalid base register in memory operand: " + reg_str;
        return false;
    }

    offset = static_cast<int32_t>(off64);
    return true;
}

static uint32_t encode_r(uint32_t rs, uint32_t rt, uint32_t rd, uint32_t shamt, uint32_t funct) {
    return (rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | funct;
}

static uint32_t encode_i(uint32_t opcode, uint32_t rs, uint32_t rt, uint16_t imm) {
    return (opcode << 26) | (rs << 21) | (rt << 16) | static_cast<uint32_t>(imm);
}

static uint32_t encode_j(uint32_t opcode, uint32_t target26) {
    return (opcode << 26) | (target26 & 0x03FFFFFFu);
}

static int instruction_word_count(const std::string &op) {
    if (op == "la") return 2;
    return 1;
}

static bool parse_op_and_args(const std::string &line,
                              std::string &op,
                              std::vector<std::string> &args) {
    std::string t = trim(line);
    if (t.empty()) return false;

    size_t split = t.find_first_of(" \t");
    if (split == std::string::npos) {
        op = to_lower(t);
        args.clear();
        return true;
    }

    op = to_lower(trim(t.substr(0, split)));
    std::string rest = trim(t.substr(split + 1));
    args = split_args(rest);
    return true;
}

static bool first_pass(const std::string &asm_path,
                       std::vector<Statement> &statements,
                       std::unordered_map<std::string, uint32_t> &symbols,
                       std::string &err) {
    std::ifstream fin(asm_path);
    if (!fin) {
        err = "Cannot open input ASM file: " + asm_path;
        return false;
    }

    statements.clear();
    symbols.clear();

    Section section = Section::None;
    uint32_t data_addr = kDataBase;
    uint32_t text_addr = kTextBase;

    std::string raw;
    int line_no = 0;
    while (std::getline(fin, raw)) {
        ++line_no;
        std::string line = trim(strip_comment(raw));
        if (line.empty()) continue;

        while (true) {
            size_t colon = line.find(':');
            size_t ws = line.find_first_of(" \t");
            bool has_label = (colon != std::string::npos) && (ws == std::string::npos || colon < ws);
            if (!has_label) break;

            std::string label = trim(line.substr(0, colon));
            if (!is_identifier(label)) {
                err = "Line " + std::to_string(line_no) + ": invalid label: " + label;
                return false;
            }
            if (symbols.find(label) != symbols.end()) {
                err = "Line " + std::to_string(line_no) + ": duplicate label: " + label;
                return false;
            }

            uint32_t addr = 0;
            if (section == Section::Data) {
                addr = data_addr;
            } else if (section == Section::Text) {
                addr = text_addr;
            } else {
                err = "Line " + std::to_string(line_no) + ": label outside .data/.text section: " + label;
                return false;
            }
            symbols[label] = addr;

            line = trim(line.substr(colon + 1));
            if (line.empty()) break;
        }

        if (line.empty()) continue;

        std::string op;
        std::vector<std::string> args;
        if (!parse_op_and_args(line, op, args)) continue;

        Statement st;
        st.section = section;
        st.line_no = line_no;
        st.op = op;
        st.args = args;
        st.is_directive = (!op.empty() && op[0] == '.');

        if (st.is_directive) {
            if (op == ".data") {
                section = Section::Data;
                st.section = section;
                st.address = data_addr;
                statements.push_back(st);
                continue;
            }
            if (op == ".text") {
                section = Section::Text;
                st.section = section;
                st.address = text_addr;
                statements.push_back(st);
                continue;
            }

            if (section == Section::None) {
                err = "Line " + std::to_string(line_no) + ": directive outside section: " + op;
                return false;
            }

            st.address = (section == Section::Data) ? data_addr : text_addr;
            statements.push_back(st);

            if (op == ".globl") {
                continue;
            } else if (op == ".word") {
                if (args.empty()) {
                    err = "Line " + std::to_string(line_no) + ": .word requires at least one value";
                    return false;
                }
                uint32_t inc = static_cast<uint32_t>(args.size()) * 4u;
                if (section == Section::Data) data_addr += inc;
                else text_addr += inc;
            } else if (op == ".space") {
                if (args.size() != 1) {
                    err = "Line " + std::to_string(line_no) + ": .space requires exactly one argument";
                    return false;
                }
                int64_t bytes = 0;
                if (!parse_int64(args[0], bytes) || bytes < 0) {
                    err = "Line " + std::to_string(line_no) + ": invalid .space size";
                    return false;
                }
                if (section == Section::Data) data_addr += static_cast<uint32_t>(bytes);
                else text_addr += static_cast<uint32_t>(bytes);
            } else {
                err = "Line " + std::to_string(line_no) + ": unsupported directive: " + op;
                return false;
            }
            continue;
        }

        if (section != Section::Text) {
            err = "Line " + std::to_string(line_no) + ": instruction outside .text section";
            return false;
        }

        st.address = text_addr;
        statements.push_back(st);
        text_addr += static_cast<uint32_t>(instruction_word_count(op)) * 4u;
    }

    return true;
}

static bool encode_instruction(const Statement &st,
                               const std::unordered_map<std::string, uint32_t> &symbols,
                               std::vector<uint32_t> &out_words,
                               std::string &err) {
    auto bad_args = [&](const std::string &msg) {
        err = "Line " + std::to_string(st.line_no) + ": " + msg;
        return false;
    };

    const std::string &op = st.op;

    if (op == "nop") {
        out_words.push_back(0x00000000u);
        return true;
    }

    if (op == "la") {
        if (st.args.size() != 2) return bad_args("la expects: la rt, label");

        uint32_t rt = 0;
        if (!parse_reg(st.args[0], rt)) return bad_args("invalid register in la: " + st.args[0]);

        uint32_t addr = 0;
        if (!parse_u32(st.args[1], symbols, addr)) return bad_args("unknown symbol/value in la: " + st.args[1]);

        uint16_t hi = static_cast<uint16_t>((addr >> 16) & 0xFFFFu);
        uint16_t lo = static_cast<uint16_t>(addr & 0xFFFFu);

        out_words.push_back(encode_i(0x0Fu, 0u, rt, hi));
        out_words.push_back(encode_i(0x0Du, rt, rt, lo));
        return true;
    }

    if (op == "add" || op == "sub" || op == "and" || op == "or" || op == "xor") {
        if (st.args.size() != 3) return bad_args(op + " expects: rd, rs, rt");

        uint32_t rd = 0, rs = 0, rt = 0;
        if (!parse_reg(st.args[0], rd) || !parse_reg(st.args[1], rs) || !parse_reg(st.args[2], rt)) {
            return bad_args("invalid register in " + op);
        }

        uint32_t funct = 0;
        if (op == "add") funct = 0x20u;
        else if (op == "sub") funct = 0x22u;
        else if (op == "and") funct = 0x24u;
        else if (op == "or") funct = 0x25u;
        else funct = 0x26u;

        out_words.push_back(encode_r(rs, rt, rd, 0u, funct));
        return true;
    }

    if (op == "sll" || op == "srl") {
        if (st.args.size() != 3) return bad_args(op + " expects: rd, rt, shamt");

        uint32_t rd = 0, rt = 0;
        if (!parse_reg(st.args[0], rd) || !parse_reg(st.args[1], rt)) {
            return bad_args("invalid register in " + op);
        }

        int64_t sh = 0;
        if (!parse_int64(st.args[2], sh) || sh < 0 || sh > 31) {
            return bad_args("invalid shift amount in " + op);
        }

        uint32_t funct = (op == "sll") ? 0x00u : 0x02u;
        out_words.push_back(encode_r(0u, rt, rd, static_cast<uint32_t>(sh), funct));
        return true;
    }

    if (op == "mult") {
        // Support both forms:
        //   mult rs, rt         (legacy: rd = $zero)
        //   mult rd, rs, rt     (explicit destination)
        if (st.args.size() != 2 && st.args.size() != 3) {
            return bad_args("mult expects: rs, rt  OR  rd, rs, rt");
        }

        uint32_t rd = 0u, rs = 0u, rt = 0u;
        if (st.args.size() == 2) {
            if (!parse_reg(st.args[0], rs) || !parse_reg(st.args[1], rt)) {
                return bad_args("invalid register in mult");
            }
        } else {
            if (!parse_reg(st.args[0], rd) || !parse_reg(st.args[1], rs) || !parse_reg(st.args[2], rt)) {
                return bad_args("invalid register in mult");
            }
        }

        out_words.push_back(encode_r(rs, rt, rd, 0u, 0x18u));
        return true;
    }

    if (op == "aesenc") {
        if (st.args.size() != 3) return bad_args("aesenc expects: rd, rs, rt");

        uint32_t rd = 0, rs = 0, rt = 0;
        if (!parse_reg(st.args[0], rd) || !parse_reg(st.args[1], rs) || !parse_reg(st.args[2], rt)) {
            return bad_args("invalid register in aesenc");
        }

        // Custom R-type funct for AES_ENC instruction.
        out_words.push_back(encode_r(rs, rt, rd, 0u, 0x3Au));
        return true;
    }

    if (op == "aesdec") {
        if (st.args.size() != 1) return bad_args("aesdec expects: rd");

        uint32_t rd = 0;
        if (!parse_reg(st.args[0], rd)) {
            return bad_args("invalid register in aesdec");
        }

        // Custom R-type funct for AES_DEC instruction.
        out_words.push_back(encode_r(0u, 0u, rd, 0u, 0x3Bu));
        return true;
    }

    if (op == "addi") {
        if (st.args.size() != 3) return bad_args("addi expects: rt, rs, imm");

        uint32_t rt = 0, rs = 0;
        if (!parse_reg(st.args[0], rt) || !parse_reg(st.args[1], rs)) {
            return bad_args("invalid register in addi");
        }

        int64_t imm = 0;
        if (!parse_int64(st.args[2], imm) || imm < -32768 || imm > 32767) {
            return bad_args("addi immediate out of range");
        }

        out_words.push_back(encode_i(0x08u, rs, rt, static_cast<uint16_t>(imm & 0xFFFF)));
        return true;
    }

    if (op == "lui") {
        if (st.args.size() != 2) return bad_args("lui expects: rt, imm");

        uint32_t rt = 0;
        if (!parse_reg(st.args[0], rt)) return bad_args("invalid register in lui");

        uint32_t imm_u32 = 0;
        if (!parse_u32(st.args[1], symbols, imm_u32) || imm_u32 > 0xFFFFu) {
            return bad_args("lui immediate out of range");
        }

        out_words.push_back(encode_i(0x0Fu, 0u, rt, static_cast<uint16_t>(imm_u32)));
        return true;
    }

    if (op == "ori") {
        if (st.args.size() != 3) return bad_args("ori expects: rt, rs, imm");

        uint32_t rt = 0, rs = 0;
        if (!parse_reg(st.args[0], rt) || !parse_reg(st.args[1], rs)) {
            return bad_args("invalid register in ori");
        }

        uint32_t imm_u32 = 0;
        if (!parse_u32(st.args[2], symbols, imm_u32) || imm_u32 > 0xFFFFu) {
            return bad_args("ori immediate out of range");
        }

        out_words.push_back(encode_i(0x0Du, rs, rt, static_cast<uint16_t>(imm_u32)));
        return true;
    }

    if (op == "lw" || op == "sw") {
        if (st.args.size() != 2) return bad_args(op + " expects: rt, offset(base)");

        uint32_t rt = 0;
        if (!parse_reg(st.args[0], rt)) return bad_args("invalid register in " + op);

        int32_t off = 0;
        uint32_t rs = 0;
        std::string mem_err;
        if (!parse_mem_operand(st.args[1], off, rs, mem_err)) return bad_args(mem_err);

        uint32_t opcode = (op == "lw") ? 0x23u : 0x2Bu;
        out_words.push_back(encode_i(opcode, rs, rt, static_cast<uint16_t>(off & 0xFFFF)));
        return true;
    }

    if (op == "beq" || op == "bne") {
        if (st.args.size() != 3) return bad_args(op + " expects: rs, rt, label");

        uint32_t rs = 0, rt = 0;
        if (!parse_reg(st.args[0], rs) || !parse_reg(st.args[1], rt)) {
            return bad_args("invalid register in " + op);
        }

        auto it = symbols.find(st.args[2]);
        if (it == symbols.end()) {
            return bad_args("unknown branch label: " + st.args[2]);
        }

        int64_t target = static_cast<int64_t>(it->second);
        int64_t next_pc = static_cast<int64_t>(st.address) + 4;
        int64_t off_words = (target - next_pc) / 4;
        if (((target - next_pc) % 4) != 0) {
            return bad_args("unaligned branch target: " + st.args[2]);
        }
        if (off_words < -32768 || off_words > 32767) {
            return bad_args("branch offset out of range: " + st.args[2]);
        }

        uint32_t opcode = (op == "beq") ? 0x04u : 0x05u;
        out_words.push_back(encode_i(opcode, rs, rt, static_cast<uint16_t>(off_words & 0xFFFF)));
        return true;
    }

    if (op == "j") {
        if (st.args.size() != 1) return bad_args("j expects: j label");

        auto it = symbols.find(st.args[0]);
        if (it == symbols.end()) {
            return bad_args("unknown jump label: " + st.args[0]);
        }

        uint32_t target = it->second >> 2;
        out_words.push_back(encode_j(0x02u, target));
        return true;
    }

    return bad_args("unsupported instruction: " + op);
}

static bool second_pass(const std::vector<Statement> &statements,
                        const std::unordered_map<std::string, uint32_t> &symbols,
                        std::vector<uint32_t> &text_words,
                        std::vector<uint32_t> &data_words,
                        std::string &err) {
    text_words.clear();
    data_words.clear();

    std::map<uint32_t, uint32_t> data_map;
    uint32_t data_cursor = kDataBase;

    for (const Statement &st : statements) {
        if (st.is_directive) {
            if (st.op == ".data" || st.op == ".text" || st.op == ".globl") {
                continue;
            }

            if (st.op == ".word") {
                for (const std::string &arg : st.args) {
                    uint32_t val = 0;
                    if (!parse_u32(arg, symbols, val)) {
                        err = "Line " + std::to_string(st.line_no) + ": invalid .word value: " + arg;
                        return false;
                    }

                    if (st.section == Section::Data) {
                        if ((data_cursor & 0x3u) != 0u) {
                            err = "Line " + std::to_string(st.line_no) + ": data cursor is not word-aligned for .word";
                            return false;
                        }
                        data_map[data_cursor] = val;
                        data_cursor += 4;
                    } else if (st.section == Section::Text) {
                        text_words.push_back(val);
                    }
                }
                continue;
            }

            if (st.op == ".space") {
                int64_t bytes = 0;
                if (!parse_int64(st.args[0], bytes) || bytes < 0) {
                    err = "Line " + std::to_string(st.line_no) + ": invalid .space size";
                    return false;
                }

                if (st.section == Section::Data) {
                    data_cursor += static_cast<uint32_t>(bytes);
                } else if (st.section == Section::Text) {
                    if ((bytes % 4) != 0) {
                        err = "Line " + std::to_string(st.line_no) + ": .space in .text must be multiple of 4";
                        return false;
                    }
                    for (int64_t i = 0; i < bytes / 4; ++i) {
                        text_words.push_back(0u);
                    }
                }
                continue;
            }

            err = "Line " + std::to_string(st.line_no) + ": unsupported directive in second pass: " + st.op;
            return false;
        }

        std::vector<uint32_t> enc;
        if (!encode_instruction(st, symbols, enc, err)) {
            return false;
        }
        text_words.insert(text_words.end(), enc.begin(), enc.end());
    }

    uint32_t data_end = data_cursor;
    if (data_end < kDataBase) data_end = kDataBase;
    if ((data_end & 0x3u) != 0u) {
        data_end = (data_end + 3u) & ~0x3u;
    }

    uint32_t data_count = (data_end - kDataBase) / 4u;
    data_words.resize(data_count, 0u);

    for (uint32_t i = 0; i < data_count; ++i) {
        uint32_t addr = kDataBase + i * 4u;
        auto it = data_map.find(addr);
        if (it != data_map.end()) {
            data_words[i] = it->second;
        }
    }

    return true;
}

static bool write_hex_file(const std::string &path, const std::vector<uint32_t> &words, std::string &err) {
    std::ofstream fout(path);
    if (!fout) {
        err = "Cannot open output file: " + path;
        return false;
    }

    for (uint32_t w : words) {
        fout << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << w << "\n";
    }

    return true;
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " input.asm text.hex data.hex\n";
        return 1;
    }

    const std::string asm_path = argv[1];
    const std::string text_hex_path = argv[2];
    const std::string data_hex_path = argv[3];

    std::vector<Statement> statements;
    std::unordered_map<std::string, uint32_t> symbols;
    std::string err;

    if (!first_pass(asm_path, statements, symbols, err)) {
        std::cerr << "[ERROR] " << err << "\n";
        return 2;
    }

    std::vector<uint32_t> text_words;
    std::vector<uint32_t> data_words;
    if (!second_pass(statements, symbols, text_words, data_words, err)) {
        std::cerr << "[ERROR] " << err << "\n";
        return 3;
    }

    if (!write_hex_file(text_hex_path, text_words, err)) {
        std::cerr << "[ERROR] " << err << "\n";
        return 4;
    }

    if (!write_hex_file(data_hex_path, data_words, err)) {
        std::cerr << "[ERROR] " << err << "\n";
        return 5;
    }

    std::cout << "[INFO] Assembled without MARS." << std::endl;
    std::cout << "[INFO] Text words: " << text_words.size() << std::endl;
    std::cout << "[INFO] Data words: " << data_words.size() << std::endl;
    std::cout << "[INFO] Wrote: " << text_hex_path << " and " << data_hex_path << std::endl;

    return 0;
}
