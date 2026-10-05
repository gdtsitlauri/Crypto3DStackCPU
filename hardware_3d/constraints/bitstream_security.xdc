# Bitstream protection for the Artix-7 (7-series) build of Crypto3DStackCPU / VTF
# (roadmap 2.5). Applied by hardware_3d/scripts/vivado_secure_bitstream.tcl.
#
# Goal: an attacker with the board and the flash cannot read or modify the
# design (and thus cannot learn where the PUF/key logic is or patch the guard).
#
#   * AES-256 bitstream encryption, key held in battery-backed RAM (BBRAM) or
#     eFUSE, never in the repository. The key file (.nky) is passed to the tcl
#     script from OUTSIDE the repository.
#   * 7-series encrypted bitstreams are also HMAC-authenticated (HKEY lives in
#     the encrypted part of the bitstream), so tampered bitstreams are rejected.
#   * Readback disabled (Level2 also blocks reconfiguration from JTAG without a
#     power cycle).
#   * JTAG disabled after configuration.
#
# NOT verified on hardware (no board in this phase). Property names follow
# AMD UG908 (Programming and Debugging) for 7-series; check them against the
# Vivado version in use before production. eFUSE programming is irreversible:
# test with BBRAM first.

# ---- encryption + authentication ----
set_property BITSTREAM.ENCRYPTION.ENCRYPT          YES   [current_design]
set_property BITSTREAM.ENCRYPTION.ENCRYPTKEYSELECT BBRAM [current_design]
# KEY0 / HKEY / STARTCBC come from the .nky key file (set by the tcl script via
# BITSTREAM.ENCRYPTION.KEYFILE); never write key material in this file.

# ---- readback / configuration interface ----
set_property BITSTREAM.READBACK.SECURITY Level2 [current_design]
set_property BITSTREAM.GENERAL.DISABLE_JTAG YES [current_design]

# ---- misc hardening ----
# Do not keep unused configuration logic alive; compress to shorten load time.
set_property BITSTREAM.GENERAL.COMPRESS FALSE [current_design]
# (compression is not allowed together with encryption on 7-series)
