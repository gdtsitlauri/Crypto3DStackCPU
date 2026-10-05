# Crypto3DStackCPU / VTF — Roadmap για το μέλλον (PhD)

Κατάσταση: 2026-10-03. Το project «παγώνει» εδώ και συνεχίζεται στο διδακτορικό.
Αυτό το αρχείο λέει **τι μένει, με ποια σειρά, πού στον κώδικα και πώς ελέγχεται**.

## Ενημέρωση 2026-10-04: η Φάση 1 και η Φάση 2 υλοποιήθηκαν, μένουν μόνο τρεξίματα και εργαστήριο

Όλα ελέγχθηκαν με δωρεάν εργαλεία (Icarus, Verilator, SymbiYosys, Yosys, Python, C++).
Αναλυτικά νούμερα: `docs/PHASE2_RESULTS_2026.md`.
Τρέξιμο όλων:
- `bash hardware_3d/scripts/run_rtl_validation.sh` (Φάση 1)
- `bash hardware_3d/scripts/run_phase2_validation.sh` (Φάση 2)
- ή `scripts/run_hardware_gate.sh` (και τα δύο, μαζί με Vivado/HLS όταν υπάρχουν)

| Στόχος | Υλοποίηση | Έλεγχος | Μένει |
|---|---|---|---|
| 1.1 ένωση | `aes128_core`, `aes_cmac32`, `vtf_key_schedule`, `crypto3d_vtf_system_top` | `tb_vtf_system`: 26 σενάρια, FIPS/NIST/HLS vectors, latency 56 κύκλοι | Vivado PPA |
| 1.2 formal | `hardware_3d/formal/` (P1–P8, abc pdr unbounded) | prove + prove_ft + cover PASS· mutation 13/13 | — |
| 1.3 κλειδιά ανά epoch/ρόλο | RTL + C++ (`setEpochKeyHierarchy`) + Python | bit-exact και στα τρία | — |
| 1.4 threat model | `docs/THREAT_MODEL_2026.md` | — | paper |
| 2.1 κρυπτογράφηση μνήμης + δέντρο | `memory_integrity_tree.sv`, `src/memory_integrity.h`, `mem_integrity_reference.py` | 9/9 επιθέσεις (bit flip, splicing, rollback, πλήρες replay, κόμβος δέντρου)· read 132 / write 239 κύκλοι | κόστος BRAM στο Vivado |
| 2.2 masked AES | `aes_sbox_masked.sv` (DOM 1ης τάξης) | προσομοιωμένο TVLA 50k: masked \|t\|=1.2 vs unmasked 221 | maskVerif/SILVER· πραγματικό TVLA (Φάση 3) |
| 2.3 fault injection | `FAULT_HARDEN=1` (guard + system) | καμπάνια SEU: unhardened 93 (τυχαία) / 86 (εξαντλητική) παραβιάσεις → hardened **0 / 0** | glitching σε πλακέτα (Φάση 3) |
| 2.4 PUF | `puf_fuzzy_extractor.sv` + μοντέλο/μελέτη | 85°C ανακατασκευή OK· REP=11 για <0,2% αποτυχία | πραγματικά RO σε πλακέτες (Φάση 3) |
| 2.5 bitstream | `constraints/bitstream_security.xdc`, `vivado_secure_bitstream.tcl` | — | μόνο σε πλακέτα |
| 2.6 ένωση με CPU | `crypto3d_vtf_cpu_bridge.sv`, `crypto3d_vtf_soc_top.sv`, traces από `programs/*.asm` | όλα τα προγράμματα σωστά από άκρη σε άκρη· ~110 κύκλοι ανά λέξη | **εύρημα:** χρειάζεται authentication ανά cache line + pipelining (επόμενο paper) |

Βασική αρχή (Kerckhoffs): ο επιτιθέμενος θεωρείται ότι ξέρει όλο το RTL και
τον κώδικα. Προστατεύονται μόνο τα **κλειδιά**. Στόχος δεν είναι «μηδέν
αδυναμίες», αλλά ρητό threat model + άμυνα για ό,τι είναι μέσα σε αυτό +
καθαρή δήλωση για ό,τι μένει εκτός.

---

## Φάση 0 — Μόνο τρεξίματα (όλα έτοιμα)

Λεπτομέρειες: `docs/HARDWARE_GATE_RUNBOOK.md`.

| Βήμα | Πώς |
|---|---|
| Lint + 3 προσομοιώσεις + 15 επιθέσεις (δωρεάν εργαλεία) | `bash hardware_3d/scripts/run_rtl_validation.sh` |
| Vitis HLS του AES-CMAC (csim/csynth/cosim/synth) | μέρος του `scripts/run_hardware_gate.sh` |
| Vivado PPA: χωρίς VTF / με VTF / μόνο guard | μέρος του `scripts/run_hardware_gate.sh` |
| Πίνακας για το paper | `results/hardware_eval/table_vtf_overhead.tex` |

Πιθανά θέματα: το HLS synthesis του `src/3d.cpp` δεν έχει τρέξει ποτέ σε Vitis.

---

## Φάση 1 — Πριν από το πρώτο paper

### 1.1 Ένωση όλων των κομματιών (κύριο αρχιτεκτονικό κενό)
- **Σήμερα:** ο guard παίρνει το `auth_ok_i` ως **εξωτερικό σήμα**· το CMAC
  είναι χωριστό (HLS)· ο `tier_sentinel_monitor` δεν είναι συνδεδεμένος· η CPU
  (C++/HLS) δεν μιλά με το RTL της μνήμης.
- **Λύση:** AES-128 + CMAC σε RTL (επαναληπτικός πυρήνας, ~11 κύκλοι/block),
  μονάδα `vtf_authenticator` που υπολογίζει το tag κάθε κάθετης μεταφοράς από
  τα πεδία (requester, op, tier, addr, payload, seq, epoch) και οδηγεί το
  `auth_ok`· σύνδεση του sentinel monitor στο `sentinel_fault_i`· νέο top
  `crypto3d_vtf_system_top`.
- **Αρχεία:** νέα `hardware_3d/rtl/aes128_core.sv`, `aes_cmac.sv`,
  `vtf_authenticator.sv`, `crypto3d_vtf_system_top.sv`· ενημέρωση
  `tb_vtf_attack_campaign.sv` ώστε η πλαστογράφηση να γίνεται με λάθος tag και
  όχι με `auth_ok=0`.
- **Έλεγχος:** τα test vectors του `src/vtf_hls_tb.cpp` σε Icarus· η καμπάνια
  επιθέσεων πάνω στο ενωμένο σύστημα· μέτρηση **καθυστέρησης ανά μεταφορά**
  σε κύκλους (κρίσιμο νούμερο για το paper).

### 1.2 Formal verification του guard
- **Λύση:** SVA properties + SymbiYosys (υπάρχει στο OSS CAD Suite):
  - ποτέ `allow` όταν `seq != last+1` (replay/gap)·
  - ποτέ `allow` όταν `epoch != active_epoch` ή `!auth_ok`·
  - μετά το `lockdown` κανένα `allow` μέχρι reset·
  - κάθε σοβαρό γεγονός → `key_zeroize` στον ίδιο κύκλο·
  - το CPU fetch δεν γράφει ποτέ· το DMA δεν αγγίζει ποτέ exec/key tier.
- **Αρχεία:** νέα `hardware_3d/formal/vertical_trust_guard.sby`,
  `vertical_trust_guard_props.sv`.
- **Έλεγχος:** `sby -f` (prove mode) περνά· αν αφαιρεθεί ένας έλεγχος από τον
  guard, το αντίστοιχο property πρέπει να αποτύχει (mutation check).

### 1.3 Ιεραρχία κλειδιών και εναλλαγή ανά epoch
- **Σήμερα:** ένα κλειδί CMAC· το device root στην προσομοίωση είναι test vector.
- **Λύση:** `K_epoch = CMAC(K_root, "VTF" ‖ epoch)`, ξεχωριστά κλειδιά ανά
  ρόλο (fetch / data / DMA / debug)· αλλαγή epoch → νέο κλειδί, παλιές
  μεταφορές άκυρες.
- **Αρχεία:** `src/vertical_trust_fabric.h`, RTL KDF στο `vtf_authenticator`.

### 1.4 Ρητό threat model στο paper
Μέσα: replay, spoofing, πλαστογράφηση, bit-flip σε TSV, θερμικές/φυσικές βλάβες,
κακόβουλο DMA/debug. Εκτός (μέχρι τη Φάση 3): power/EM side channels,
glitching με μέτρηση, invasive probing, πραγματικό 3D silicon.

---

## Φάση 2 — Επεκτάσεις διδακτορικού (υλοποιούνται και ελέγχονται σε προσομοίωση)

### 2.1 Κρυπτογράφηση μνήμης + δέντρο integrity
- **Σήμερα:** προστατεύονται οι **μεταφορές**, όχι τα δεδομένα «σε ηρεμία».
  Ένας επιτιθέμενος που γράφει απευθείας στη μνήμη (εκτός VTF) μπορεί να
  επαναφέρει παλιό περιεχόμενο.
- **Λύση:** AES-CTR ανά block με counter + Merkle/Bonsai tree με τη ρίζα στο
  key tier· έλεγχος σε κάθε ανάγνωση.
- **Αρχεία:** C++ μοντέλο σε `src/vertical_trust_fabric.h`, RTL
  `hardware_3d/rtl/memory_integrity_tree.sv`.
- **Έλεγχος:** επιθέσεις memory replay / splicing στο testbench· κόστος σε
  καθυστέρηση και BRAM στο Vivado.

### 2.2 Masked AES (άμυνα σε power/EM side channels)
- **Λύση:** threshold implementation / Domain-Oriented Masking πρώτης τάξης
  για το AES S-box με φρέσκια τυχαιότητα (TRNG/PRNG).
- **Έλεγχος χωρίς εργαστήριο:** προσομοιωμένο TVLA πάνω σε toggle counts / Hamming
  distance του netlist (Yosys + δικό μας script)· έλεγχος probing security με
  εργαλείο τύπου maskVerif / SILVER.
- **Έλεγχος με εργαστήριο:** πραγματικό TVLA με παλμογράφο (Φάση 3).

### 2.3 Ανίχνευση fault injection
- **Λύση:** διπλός υπολογισμός του CMAC (ή inverse check), parity/ECC στα
  registers του guard και στο `last_sequence`, έλεγχοι συνέπειας του FSM,
  ανιχνευτές ρολογιού.
- **Έλεγχος:** καμπάνια fault injection σε προσομοίωση (bit-flip σε κάθε
  register, σε κάθε κύκλο) → ποσοστό ανίχνευσης.

### 2.4 Κλειδί από PUF / eFUSE (το κλειδί να μην είναι ποτέ στο bitstream)
- **Λύση:** RO-PUF ή arbiter PUF σε RTL + fuzzy extractor (helper data, BCH ECC)
  → `K_root`. Εναλλακτικά eFUSE/BBRAM του Artix-7.
- **Έλεγχος:** λειτουργικός σε προσομοίωση με μοντέλο θορύβου· πραγματική
  αξιοπιστία/μοναδικότητα μόνο σε πλακέτες (Φάση 3).

### 2.5 Προστασία του bitstream (reverse engineering του FPGA)
- **Λύση:** ρυθμίσεις Vivado: `BITSTREAM.ENCRYPTION.ENCRYPT YES`, AES-256 κλειδί
  σε BBRAM/eFUSE, HMAC authentication, `BITSTREAM.READBACK.SECURITY Level2`,
  απενεργοποίηση/κλείδωμα JTAG.
- **Αρχεία:** νέο `hardware_3d/constraints/bitstream_security.xdc` + βήμα στο
  `vivado_synth.tcl` (`write_bitstream`).
- **Έλεγχος:** μόνο σε πλακέτα (Φάση 3).

### 2.6 Ένωση με την CPU
- Σύνδεση της HLS CPU (`Crypto3DStackCPU_top`) με το `crypto3d_vtf_system_top`
  μέσω του `crypto3d_memory_bridge_stub.sv` (σήμερα stub) → πλήρες σύστημα
  CPU + VTF + μνήμη, benchmarks προγραμμάτων (`programs/*.asm`) με/χωρίς VTF.

---

## Φάση 3 — Χρειάζεται εργαστήριο / εξωτερικούς (δεν λύνεται μόνο με κώδικα)

| Θέμα | Τι χρειάζεται |
|---|---|
| Πραγματικό TVLA (power/EM) | πλακέτα (π.χ. ChipWhisperer CW305 / Arty) + παλμογράφος |
| Glitching ρολογιού/τάσης | ChipWhisperer ή αντίστοιχο |
| PUF αξιοπιστία/μοναδικότητα | πολλές πλακέτες, θερμοκρασίες |
| Bitstream encryption, JTAG lock | πραγματική πλακέτα Artix-7 |
| Invasive probing, logic locking / camouflaging | μόνο για ASIC — εκτός εμβέλειας |
| Πραγματικό 3D τσιπ με TSV | foundry / PDK — εκτός εμβέλειας |
| Systematic literature/patent novelty audit | διάβασμα (3D-IC security, TSV authentication, secure memory) |

---

## Εργαλεία

- Δωρεάν: OSS CAD Suite (Verilator, Icarus, Yosys+slang, SymbiYosys),
  CMake + C++ compiler, Python.
- AMD: Vivado / Vitis HLS (δωρεάν έκδοση για Artix-7).
- Εργαστήριο (Φάση 3): πλακέτα FPGA, ChipWhisperer, παλμογράφος.

## Προτεινόμενη σειρά

1. Φάση 0 (τρεξίματα).
2. 1.1 (ένωση) + 1.2 (formal) + 1.3 (κλειδιά) → **πρώτο paper**.
3. 2.1 + 2.3 + 2.6 → δεύτερο paper (πλήρες ασφαλές σύστημα).
4. 2.2 + 2.4 + 2.5 + Φάση 3 σε εργαστήριο → τρίτο paper (φυσικές επιθέσεις).
