# Multi-Layer 3D Stacked Memory Upgrade Patch

This patch upgrades the project from a layer-0-only memory abstraction to a real fixed-size multi-layer 3D-stacked-memory abstraction while preserving the already validated CPU execution flow on layer 0.

The correct scientific wording after this patch is:

> Multi-layer-capable 3D-stacked-memory abstraction with a validated secure execution path on layer 0.

Do **not** claim fabricated 3D IC hardware. That remains future work.

---

## 1. Replace `3d.h`

Replace your current `3d.h` with the provided `3d_multilayer.h` file, renaming it to:

```text
3d.h
```

Main changes:

| Feature | Old behavior | New behavior |
|---|---|---|
| `MAX_LAYERS` | 1 | 4 |
| Layer normalization | every layer mapped to layer 0 | real layer validation |
| `read/write` | layer argument ignored | layer argument respected |
| `encryptLayer/decryptLayer` | layer 0 only | per-layer encryption |
| `hideKeyInLayer` | layer 0 only | per-layer key hiding |
| `processing_layer` | active layer only | any valid layer |
| `copyLayer` | effectively no-op layer copy | real layer-to-layer copy |
| `hardwareObfuscate` | active layer only | all valid layers |
| layer keys | fixed layer-0 constants | derived per-layer key words |

---

## 2. Patch `3d.cpp`

### 2.1 Static size definition

Find:

```cpp
#define MAX_LAYERS   1
```

Replace with:

```cpp
#define MAX_LAYERS   4
```

If your `3d.cpp` already includes `3d.h` before this macro block, the cleanest version is:

```cpp
#ifndef MAX_LAYERS
#define MAX_LAYERS   4
#endif
```

---

### 2.2 Global memory object

Find:

```cpp
StackedMemory3D stackedMemory(1, MEM_SIZE); // Single layer, 1024 words
```

Replace with:

```cpp
StackedMemory3D stackedMemory(MAX_LAYERS, MEM_SIZE); // 4-layer 3D stack, 1024 words/layer
```

This does **not** force the CPU to execute from all layers. The default secure image path still uses layer 0 unless `CPU_set_layers()` is used.

---

### 2.3 CPU layer selector

Find:

```cpp
extern "C" void CPU_set_layers(uint32_t il, uint32_t dl) {
    (void)il;
    (void)dl;
    // Single-layer mode: always use layer 0.
    instr_layer = 0;
    data_layer  = 0;
    invalidateCaches();
}
```

Replace with:

```cpp
extern "C" void CPU_set_layers(uint32_t il, uint32_t dl) {
    if (il < stackedMemory.getNumLayers() && dl < stackedMemory.getNumLayers()) {
        instr_layer = il;
        data_layer  = dl;
    } else {
        instr_layer = 0;
        data_layer  = 0;
        stackedMemory.lockSecurity("BAD LAYER SELECT");
    }
    invalidateCaches();
}
```

---

## 3. Optional but recommended: make secure functions layer-aware

Several secure functions currently force `active_layer = 0`. This is safe for the validated flow, but for a full multi-layer abstraction they should honor their `layer` parameter.

### 3.1 `secure_validate_image`

Find:

```cpp
extern "C" int secure_validate_image(uint32_t layer) {
    (void)layer;
    const uint32_t active_layer = 0;
```

Replace with:

```cpp
extern "C" int secure_validate_image(uint32_t layer) {
    if (layer >= stackedMemory.getNumLayers()) {
        stackedMemory.lockSecurity("BAD VALIDATE LAYER");
        return -100;
    }
    const uint32_t active_layer = layer;
```

---

### 3.2 `extract_key_from_large_block`

Find:

```cpp
extern "C" int extract_key_from_large_block(uint32_t layer, uint32_t key[4]) {
    (void)layer;
    const uint32_t active_layer = 0;
```

Replace with:

```cpp
extern "C" int extract_key_from_large_block(uint32_t layer, uint32_t key[4]) {
    if (layer >= stackedMemory.getNumLayers()) {
        for (int i = 0; i < 4; ++i) key[i] = 0;
        stackedMemory.lockSecurity("BAD EXTRACT LAYER");
        return -100;
    }
    const uint32_t active_layer = layer;
```

---

### 3.3 `create_large_block_with_key`

Find:

```cpp
extern "C" int create_large_block_with_key(uint32_t layer, uint32_t key[4]) {
    (void)layer;
    const uint32_t active_layer = 0;
```

Replace with:

```cpp
extern "C" int create_large_block_with_key(uint32_t layer, uint32_t key[4]) {
    if (layer >= stackedMemory.getNumLayers()) {
        stackedMemory.lockSecurity("BAD CREATE LAYER");
        return -100;
    }
    const uint32_t active_layer = layer;
```

---

## 4. What should still remain layer 0?

The validated default pipeline should still load and execute from layer 0 unless a test explicitly selects another layer.

This keeps the previous regression result meaningful:

```text
[ALL REGRESSION TESTS PASSED]
```

while making the memory abstraction correctly multi-layer-capable.

---

## 5. Add the multi-layer memory test

Add the provided:

```text
multilayer_memory_test.cpp
run_multilayer_memory_test.ps1
```

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_multilayer_memory_test.ps1
```

Expected final marker:

```text
[MULTILAYER TEST PASS]
```

---

## 6. Then rerun the full regression

After applying the patch:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_all_tests.ps1
```

Expected final marker:

```text
[ALL REGRESSION TESTS PASSED]
```

If both pass, the correct state becomes:

```text
Core CPU path:                        READY
Software security validation:         READY
Multi-layer 3D memory abstraction:    READY
Validated execution layer:            Layer 0
Future work:                          FPGA/Vitis/Vivado/Artix-7 + fabricated/physical 3D hardware
```
