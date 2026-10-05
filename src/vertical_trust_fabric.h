#ifndef CRYPTO3D_VERTICAL_TRUST_FABRIC_H
#define CRYPTO3D_VERTICAL_TRUST_FABRIC_H

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "3d.h"
#include "aes_cmac.h"

// Vertical Trust Fabric (VTF)
// ---------------------------
// Research-grade software/HLS model for protecting traffic across logical
// 3D tiers. It provides:
//   * per-tier role based access control;
//   * AES-CMAC authenticated request/response packets;
//   * monotonic sequence based replay rejection;
//   * layer/operation/epoch binding inside the authentication tag;
//   * sentinel canaries;
//   * thermal/fault trip modelling;
//   * severe-event zeroization of the key/metadata tier.
//
// This model is deliberately conservative in its claims. It models mechanisms
// needed by a future 3D implementation; it is not fabricated TSV security and
// it is not a side-channel evaluation.
namespace crypto3d {

enum class VtfRequester : uint8_t {
    CPU_FETCH = 0,
    CPU_DATA  = 1,
    SECURITY  = 2,
    DMA       = 3,
    DEBUG     = 4,
    COUNT     = 5
};

enum class VtfOperation : uint8_t {
    READ  = 0,
    WRITE = 1
};

enum class VtfTierRole : uint8_t {
    INSTRUCTION = 0,
    DATA        = 1,
    KEY_METADATA= 2,
    SENTINEL    = 3
};

enum class VtfDenyReason : uint8_t {
    NONE = 0,
    LOCKDOWN,
    INVALID_FIELD,
    POLICY,
    BAD_TAG,
    REPLAY,
    EPOCH,
    THERMAL,
    PHYSICAL_FAULT,
    SENTINEL
};

struct VtfRequest {
    VtfRequester requester = VtfRequester::CPU_DATA;
    VtfOperation operation = VtfOperation::READ;
    uint8_t layer = 0;
    uint16_t reserved = 0;
    uint32_t addr = 0;
    uint32_t data = 0;
    uint32_t sequence = 0;
    uint32_t epoch = 1;
    uint32_t route_nonce = 0;
    uint32_t tag[4] = {0, 0, 0, 0};
};

struct VtfResponse {
    VtfRequester requester = VtfRequester::CPU_DATA;
    VtfOperation operation = VtfOperation::READ;
    uint8_t layer = 0;
    uint8_t status = 0;
    uint32_t addr = 0;
    uint32_t data = 0;
    uint32_t sequence = 0;
    uint32_t epoch = 1;
    uint32_t route_nonce = 0;
    uint32_t tag[4] = {0, 0, 0, 0};
};

struct VtfCounters {
    uint32_t accepted = 0;
    uint32_t policy_denied = 0;
    uint32_t bad_tag = 0;
    uint32_t replay = 0;
    uint32_t epoch_mismatch = 0;
    uint32_t thermal_trips = 0;
    uint32_t physical_faults = 0;
    uint32_t sentinel_trips = 0;
    uint32_t lockdown_denied = 0;
};

class VerticalTrustFabric {
private:
    static constexpr size_t REQUESTER_COUNT = (size_t)VtfRequester::COUNT;
    static constexpr size_t SENTINEL_COUNT = 8;

    StackedMemory3D* memory_ = nullptr;
    VtfTierRole roles_[MAX_LAYERS] = {
        VtfTierRole::INSTRUCTION,
        VtfTierRole::DATA,
        VtfTierRole::KEY_METADATA,
        VtfTierRole::SENTINEL
    };

    // Simulation/test root. A physical design must source this from a device
    // root (PUF/eFuse/BBRAM/secure element) that is not software readable.
    uint32_t root_key_[4] = {
        0x2B7E1516u, 0x28AED2A6u, 0xABF71588u, 0x09CF4F3Cu
    };
    uint32_t req_key_[4]  = {0,0,0,0};
    uint32_t rsp_key_[4]  = {0,0,0,0};
    // Optional epoch/role key hierarchy (roadmap 1.3, mirrored by hardware_3d/rtl/vtf_key_schedule.sv
    // and hardware_3d/scripts/vtf_reference.py):
    //   K_req[r,e] = AES_{K_req}("VTFE" || e || r || "KDF1"), K_rsp[e] = AES_{K_rsp}("VTFE" || e || "RSP0" || "KDF1")
    bool epoch_keys_enabled_ = false;
    uint32_t base_rsp_key_[4] = {0,0,0,0};
    uint32_t epoch_req_key_[5][4] = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}};

    uint32_t tx_seq_[REQUESTER_COUNT] = {0,0,0,0,0};
    uint32_t rx_seq_[REQUESTER_COUNT] = {0,0,0,0,0};
    uint32_t epoch_ = 1u;

    bool lockdown_ = false;
    bool debug_unlocked_ = false;
    bool zeroize_on_severe_ = true;
    VtfDenyReason last_reason_ = VtfDenyReason::NONE;
    VtfCounters counters_{};

    int32_t temperature_mC_[MAX_LAYERS] = {25000,25000,25000,25000};
    int32_t max_temperature_mC_ = 90000;

    size_t sentinel_addr_[SENTINEL_COUNT] = {0,0,0,0,0,0,0,0};
    uint32_t sentinel_value_[SENTINEL_COUNT] = {0,0,0,0,0,0,0,0};
    bool sentinels_installed_ = false;

    static inline size_t requesterIndex(VtfRequester r) {
        return (size_t)r;
    }

    static inline void store32(uint8_t* p, uint32_t x) {
        p[0] = (uint8_t)((x >> 24) & 0xFFu);
        p[1] = (uint8_t)((x >> 16) & 0xFFu);
        p[2] = (uint8_t)((x >> 8) & 0xFFu);
        p[3] = (uint8_t)(x & 0xFFu);
    }

    void deriveDomainKeys() {
        const uint32_t req_domain[4] = {0x56544652u, 0x45515545u, 0x53544B31u, 0x00000001u}; // "VTFREQUESTK1"
        const uint32_t rsp_domain[4] = {0x56544652u, 0x4553504Fu, 0x4E53454Bu, 0x00000001u}; // "VTFRESPONSEK"
        uint32_t root_local[4] = {root_key_[0], root_key_[1], root_key_[2], root_key_[3]};
        uint32_t req_in[4] = {req_domain[0], req_domain[1], req_domain[2], req_domain[3]};
        uint32_t rsp_in[4] = {rsp_domain[0], rsp_domain[1], rsp_domain[2], rsp_domain[3]};
        aes_encrypt_block(req_in, root_local, req_key_);
        aes_encrypt_block(rsp_in, root_local, rsp_key_);
        for (int i = 0; i < 4; ++i) root_local[i] = 0u;
        for (int i = 0; i < 4; ++i) base_rsp_key_[i] = rsp_key_[i];
        if (epoch_keys_enabled_) deriveEpochKeys();
    }

    void deriveEpochKeys() {
        for (size_t r = 0; r < REQUESTER_COUNT; ++r) {
            uint32_t in[4] = {0x56544645u, epoch_, (uint32_t)r, 0x4B444631u};   // "VTFE" e r "KDF1"
            uint32_t k[4] = {req_key_[0], req_key_[1], req_key_[2], req_key_[3]};
            aes_encrypt_block(in, k, epoch_req_key_[r]);
        }
        uint32_t in[4] = {0x56544645u, epoch_, 0x52535030u, 0x4B444631u};        // "VTFE" e "RSP0" "KDF1"
        uint32_t k[4] = {base_rsp_key_[0], base_rsp_key_[1], base_rsp_key_[2], base_rsp_key_[3]};
        aes_encrypt_block(in, k, rsp_key_);
    }

    const uint32_t* requestKey(VtfRequester r) const {
        const size_t idx = requesterIndex(r);
        if (epoch_keys_enabled_ && idx < REQUESTER_COUNT) return epoch_req_key_[idx];
        return req_key_;
    }

    uint32_t makeRouteNonce(VtfRequester r, uint32_t seq, uint8_t layer) const {
        uint32_t x = 0xC3D5A17Eu ^ (uint32_t)r * 0x9E3779B9u;
        x ^= seq * 0x85EBCA6Bu;
        x ^= (uint32_t)layer * 0xC2B2AE35u;
        x ^= epoch_ * 0x27D4EB2Du;
        x ^= x >> 16;
        x *= 0x7FEB352Du;
        x ^= x >> 15;
        x *= 0x846CA68Bu;
        x ^= x >> 16;
        return x;
    }

    void serializeRequest(const VtfRequest& req, uint8_t out[32]) const {
        for (int i = 0; i < 32; ++i) out[i] = 0u;
        out[0] = 0xC3u;
        out[1] = 0xD1u;
        out[2] = (uint8_t)req.requester;
        out[3] = (uint8_t)req.operation;
        out[4] = req.layer;
        store32(&out[8], req.addr);
        store32(&out[12], req.data);
        store32(&out[16], req.sequence);
        store32(&out[20], req.epoch);
        store32(&out[24], req.route_nonce);
        store32(&out[28], 0x56544631u); // "VTF1"
    }

    void serializeResponse(const VtfResponse& rsp, uint8_t out[32]) const {
        for (int i = 0; i < 32; ++i) out[i] = 0u;
        out[0] = 0xC3u;
        out[1] = 0xD2u;
        out[2] = (uint8_t)rsp.requester;
        out[3] = (uint8_t)rsp.operation;
        out[4] = rsp.layer;
        out[5] = rsp.status;
        store32(&out[8], rsp.addr);
        store32(&out[12], rsp.data);
        store32(&out[16], rsp.sequence);
        store32(&out[20], rsp.epoch);
        store32(&out[24], rsp.route_nonce);
        store32(&out[28], 0x56544632u); // "VTF2"
    }

    void signRequest(VtfRequest& req) const {
        uint8_t msg[32];
        serializeRequest(req, msg);
        aes_cmac_128(requestKey(req.requester), msg, sizeof(msg), req.tag);
    }

    void signResponse(VtfResponse& rsp) const {
        uint8_t msg[32];
        serializeResponse(rsp, msg);
        aes_cmac_128(rsp_key_, msg, sizeof(msg), rsp.tag);
    }

    bool requestTagValid(const VtfRequest& req) const {
        VtfRequest tmp = req;
        signRequest(tmp);
        return cmac_tag_equal(tmp.tag, req.tag);
    }

    bool requesterValid(VtfRequester r) const {
        return requesterIndex(r) < REQUESTER_COUNT;
    }

    bool policyAllows(const VtfRequest& req) const {
        if (req.layer >= MAX_LAYERS) return false;
        VtfTierRole role = roles_[req.layer];
        switch (req.requester) {
            case VtfRequester::CPU_FETCH:
                return req.operation == VtfOperation::READ && role == VtfTierRole::INSTRUCTION;
            case VtfRequester::CPU_DATA:
                return role == VtfTierRole::DATA;
            case VtfRequester::SECURITY:
                return true;
            case VtfRequester::DMA:
                return role == VtfTierRole::DATA;
            case VtfRequester::DEBUG:
                if (!debug_unlocked_) return false;
                return role == VtfTierRole::INSTRUCTION || role == VtfTierRole::DATA;
            default:
                return false;
        }
    }

    void zeroizeCriticalTier() {
        if (!memory_ || !zeroize_on_severe_) return;
        for (size_t l = 0; l < memory_->getNumLayers() && l < MAX_LAYERS; ++l) {
            if (roles_[l] == VtfTierRole::KEY_METADATA) {
                memory_->clearLayer(l);
                memory_->setLayerAccess(l, false);
            }
        }
    }

    void trip(VtfDenyReason reason, bool severe) {
        last_reason_ = reason;
        if (severe) {
            lockdown_ = true;
            zeroizeCriticalTier();
        }
    }

    bool validateRequest(const VtfRequest& req) {
        if (lockdown_) {
            ++counters_.lockdown_denied;
            last_reason_ = VtfDenyReason::LOCKDOWN;
            return false;
        }
        if (!requesterValid(req.requester) || req.layer >= MAX_LAYERS || !memory_ ||
            req.layer >= memory_->getNumLayers() || req.addr >= memory_->getNumWords()) {
            ++counters_.policy_denied;
            trip(VtfDenyReason::INVALID_FIELD, true);
            return false;
        }
        if (req.epoch != epoch_) {
            ++counters_.epoch_mismatch;
            trip(VtfDenyReason::EPOCH, true);
            return false;
        }
        if (!requestTagValid(req)) {
            ++counters_.bad_tag;
            trip(VtfDenyReason::BAD_TAG, true);
            return false;
        }
        const size_t idx = requesterIndex(req.requester);
        if (req.sequence != rx_seq_[idx] + 1u) {
            ++counters_.replay;
            trip(VtfDenyReason::REPLAY, true);
            return false;
        }
        // An authenticated request consumes its sequence even when policy
        // denies it. This keeps requester/receiver sequence state synchronized
        // while preserving non-destructive authorization failure.
        rx_seq_[idx] = req.sequence;
        if (!policyAllows(req)) {
            ++counters_.policy_denied;
            last_reason_ = VtfDenyReason::POLICY;
            return false;
        }
        ++counters_.accepted;
        last_reason_ = VtfDenyReason::NONE;
        return true;
    }

public:
    explicit VerticalTrustFabric(StackedMemory3D& mem) : memory_(&mem) {
        deriveDomainKeys();
    }

    void setRootKeyForSimulation(const uint32_t key[4]) {
        if (!key) return;
        for (int i = 0; i < 4; ++i) root_key_[i] = key[i];
        deriveDomainKeys();
        resetProtocolStateForSimulation();
    }

    void setTierRole(size_t layer, VtfTierRole role) {
        if (layer >= MAX_LAYERS) return;
        roles_[layer] = role;
    }

    VtfTierRole tierRole(size_t layer) const {
        return (layer < MAX_LAYERS) ? roles_[layer] : VtfTierRole::SENTINEL;
    }

    void setDebugUnlocked(bool enabled) { debug_unlocked_ = enabled; }
    void setZeroizeOnSevere(bool enabled) { zeroize_on_severe_ = enabled; }

    // Enable the per-epoch, per-requester key hierarchy (keys are re-derived now and on every epoch advance).
    void setEpochKeyHierarchy(bool enabled) {
        epoch_keys_enabled_ = enabled;
        deriveDomainKeys();
    }
    bool epochKeyHierarchy() const { return epoch_keys_enabled_; }
    // Test-only accessors (simulation): working keys of the current epoch.
    void requestKeyForTest(VtfRequester r, uint32_t out[4]) const {
        const uint32_t* k = requestKey(r);
        for (int i = 0; i < 4; ++i) out[i] = k[i];
    }
    void responseKeyForTest(uint32_t out[4]) const { for (int i = 0; i < 4; ++i) out[i] = rsp_key_[i]; }
    void setMaxTemperatureMilliC(int32_t value) { if (value > 0) max_temperature_mC_ = value; }

    uint32_t epoch() const { return epoch_; }
    bool isLockedDown() const { return lockdown_; }
    VtfDenyReason lastDenyReason() const { return last_reason_; }
    const VtfCounters& counters() const { return counters_; }

    void advanceEpoch() {
        ++epoch_;
        if (epoch_keys_enabled_) deriveEpochKeys();
        for (size_t i = 0; i < REQUESTER_COUNT; ++i) {
            tx_seq_[i] = 0u;
            rx_seq_[i] = 0u;
        }
    }

    VtfRequest issueRead(VtfRequester requester, uint8_t layer, uint32_t addr) {
        VtfRequest req;
        req.requester = requester;
        req.operation = VtfOperation::READ;
        req.layer = layer;
        req.addr = addr;
        const size_t idx = requesterIndex(requester);
        req.sequence = (idx < REQUESTER_COUNT) ? ++tx_seq_[idx] : 0u;
        req.epoch = epoch_;
        req.route_nonce = makeRouteNonce(requester, req.sequence, layer);
        signRequest(req);
        return req;
    }

    VtfRequest issueWrite(VtfRequester requester, uint8_t layer, uint32_t addr, uint32_t data) {
        VtfRequest req;
        req.requester = requester;
        req.operation = VtfOperation::WRITE;
        req.layer = layer;
        req.addr = addr;
        req.data = data;
        const size_t idx = requesterIndex(requester);
        req.sequence = (idx < REQUESTER_COUNT) ? ++tx_seq_[idx] : 0u;
        req.epoch = epoch_;
        req.route_nonce = makeRouteNonce(requester, req.sequence, layer);
        signRequest(req);
        return req;
    }

    bool execute(const VtfRequest& req, VtfResponse& rsp) {
        rsp.requester = req.requester;
        rsp.operation = req.operation;
        rsp.layer = req.layer;
        rsp.addr = req.addr;
        rsp.sequence = req.sequence;
        rsp.epoch = req.epoch;
        rsp.route_nonce = req.route_nonce;
        rsp.data = 0u;
        rsp.status = 1u;

        if (!validateRequest(req)) {
            rsp.status = 0u;
            signResponse(rsp);
            return false;
        }

        if (req.operation == VtfOperation::READ) {
            rsp.data = memory_->read(req.layer, req.addr);
        } else {
            memory_->write(req.layer, req.addr, req.data);
            rsp.data = req.data;
        }
        signResponse(rsp);
        return true;
    }

    bool verifyResponse(const VtfResponse& rsp) const {
        VtfResponse tmp = rsp;
        signResponse(tmp);
        return cmac_tag_equal(tmp.tag, rsp.tag);
    }

    bool verifyResponseForRequest(const VtfRequest& req, const VtfResponse& rsp) const {
        if (!verifyResponse(rsp)) return false;
        return rsp.requester == req.requester &&
               rsp.operation == req.operation &&
               rsp.layer == req.layer &&
               rsp.addr == req.addr &&
               rsp.sequence == req.sequence &&
               rsp.epoch == req.epoch &&
               rsp.route_nonce == req.route_nonce;
    }

    bool installSentinels() {
        if (!memory_) return false;
        size_t sentinel_layer = MAX_LAYERS;
        for (size_t l = 0; l < memory_->getNumLayers() && l < MAX_LAYERS; ++l) {
            if (roles_[l] == VtfTierRole::SENTINEL) { sentinel_layer = l; break; }
        }
        if (sentinel_layer >= memory_->getNumLayers()) return false;
        if (memory_->getNumWords() < SENTINEL_COUNT) return false;

        for (size_t i = 0; i < SENTINEL_COUNT; ++i) {
            sentinel_addr_[i] = memory_->getNumWords() - 1u - i;
            uint8_t msg[16] = {0};
            store32(&msg[0], epoch_);
            store32(&msg[4], (uint32_t)sentinel_layer);
            store32(&msg[8], (uint32_t)sentinel_addr_[i]);
            store32(&msg[12], (uint32_t)i ^ 0x53454E54u);
            uint32_t tag[4];
            aes_cmac_128(req_key_, msg, sizeof(msg), tag);
            sentinel_value_[i] = tag[i & 3u] ^ tag[(i + 1u) & 3u];
            memory_->write(sentinel_layer, sentinel_addr_[i], sentinel_value_[i]);
        }
        sentinels_installed_ = true;
        return true;
    }

    bool verifySentinels() {
        if (!sentinels_installed_ || !memory_) return false;
        size_t sentinel_layer = MAX_LAYERS;
        for (size_t l = 0; l < memory_->getNumLayers() && l < MAX_LAYERS; ++l) {
            if (roles_[l] == VtfTierRole::SENTINEL) { sentinel_layer = l; break; }
        }
        if (sentinel_layer >= memory_->getNumLayers()) return false;

        for (size_t i = 0; i < SENTINEL_COUNT; ++i) {
            if (memory_->rawRead(sentinel_layer, sentinel_addr_[i]) != sentinel_value_[i]) {
                ++counters_.sentinel_trips;
                trip(VtfDenyReason::SENTINEL, true);
                return false;
            }
        }
        return true;
    }

    void updateTemperatureMilliC(size_t layer, int32_t temperature_mC) {
        if (layer >= MAX_LAYERS) return;
        temperature_mC_[layer] = temperature_mC;
        if (temperature_mC > max_temperature_mC_) {
            ++counters_.thermal_trips;
            trip(VtfDenyReason::THERMAL, true);
        }
    }

    void reportPhysicalFault(size_t layer, size_t addr, uint32_t fault_mask) {
        (void)addr;
        (void)fault_mask;
        if (layer >= MAX_LAYERS) return;
        ++counters_.physical_faults;
        trip(VtfDenyReason::PHYSICAL_FAULT, true);
    }

    // Simulation/test-only reset. A physical implementation should require a
    // secure reset/boot sequence and root re-establishment instead.
    void resetProtocolStateForSimulation() {
        lockdown_ = false;
        last_reason_ = VtfDenyReason::NONE;
        counters_ = VtfCounters{};
        for (size_t i = 0; i < REQUESTER_COUNT; ++i) {
            tx_seq_[i] = 0u;
            rx_seq_[i] = 0u;
        }
        if (memory_) {
            for (size_t l = 0; l < memory_->getNumLayers(); ++l) memory_->setLayerAccess(l, true);
        }
    }
};

} // namespace crypto3d

#endif
