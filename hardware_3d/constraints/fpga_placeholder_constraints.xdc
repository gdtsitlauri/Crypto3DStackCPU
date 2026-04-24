# Crypto3DStackCPU constraints for Xilinx/AMD AC701 Artix-7 Evaluation Kit
# Board:  EK-A7-AC701-G
# Device: xc7a200tfbg676-2
# Ref:    https://www.amd.com/en/products/adaptive-socs-and-fpgas/evaluation-boards/ek-a7-ac701-g.html
#
# This XDC provides the baseline I/O and clocking for running the generated
# Vitis HLS IP (Crypto3DStackCPU_top) on the AC701 board. Adjust or comment
# out any line that conflicts with your top-level integration (for example,
# if Crypto3DStackCPU_top is wrapped inside a block design that already owns
# the board clock or reset).

# --------------------------------------------------------------------------
# Device / bitstream
# --------------------------------------------------------------------------
set_property CFGBVS         VCCO   [current_design]
set_property CONFIG_VOLTAGE 3.3    [current_design]
set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4 [current_design]

# --------------------------------------------------------------------------
# Primary 200 MHz LVDS differential system clock (AC701: SYSCLK_P/N on R3/P3)
# --------------------------------------------------------------------------
# The AC701 ships a 200 MHz LVDS oscillator on the SYSCLK pair. The CPU
# core runs at 100 MHz, so in a block design you would typically feed
# sys_clk_p/n into an MMCM/Clocking Wizard and connect its 100 MHz output
# to Crypto3DStackCPU_top/clk.
set_property -dict {PACKAGE_PIN R3 IOSTANDARD LVDS_25} [get_ports sys_clk_p]
set_property -dict {PACKAGE_PIN P3 IOSTANDARD LVDS_25} [get_ports sys_clk_n]
create_clock -period 5.000 -name sys_clk [get_ports sys_clk_p]
set_input_jitter sys_clk 0.050

# --------------------------------------------------------------------------
# CPU core clock (derived, 100 MHz)
# --------------------------------------------------------------------------
# If your top wrapper directly consumes a 100 MHz clock (e.g. from an MMCM
# inside the block design), Vitis HLS will export `ap_clk` / `clk` with a
# 10 ns target. Use the following two lines when Crypto3DStackCPU_top is
# the top-level RTL (not inside a block design):
# create_clock -period 10.000 -name cpu_clk [get_ports clk]
# set_clock_uncertainty -setup 0.200 [get_clocks cpu_clk]

# --------------------------------------------------------------------------
# Reset button (AC701: CPU_RESET on U4, active-high)
# --------------------------------------------------------------------------
# Crypto3DStackCPU_top uses an active-low rst_n at RTL level; invert in
# logic if needed.
set_property -dict {PACKAGE_PIN U4 IOSTANDARD LVCMOS18} [get_ports cpu_reset]

# --------------------------------------------------------------------------
# Status LEDs (AC701: GPIO_LED_[0..3])
# --------------------------------------------------------------------------
# Wire CPU status bits (security_lock, key_fail, retired_nonzero, running)
# to the four user LEDs for visual confirmation after secure boot.
# set_property -dict {PACKAGE_PIN M26 IOSTANDARD LVCMOS33} [get_ports {led[0]}]
# set_property -dict {PACKAGE_PIN T24 IOSTANDARD LVCMOS33} [get_ports {led[1]}]
# set_property -dict {PACKAGE_PIN T25 IOSTANDARD LVCMOS33} [get_ports {led[2]}]
# set_property -dict {PACKAGE_PIN R26 IOSTANDARD LVCMOS33} [get_ports {led[3]}]

# --------------------------------------------------------------------------
# UART (AC701: USB-UART via Silicon Labs CP2103)
# --------------------------------------------------------------------------
# Useful when Crypto3DStackCPU_top is wrapped behind an AXI UART for
# runtime log streaming. Leave commented unless a UART wrapper is included.
# set_property -dict {PACKAGE_PIN U19 IOSTANDARD LVCMOS18} [get_ports uart_tx]
# set_property -dict {PACKAGE_PIN T19 IOSTANDARD LVCMOS18} [get_ports uart_rx]

# --------------------------------------------------------------------------
# Implementation directives for the encrypted memory path
# --------------------------------------------------------------------------
# Prefer BRAM for the 4-layer stacked-memory abstraction (4 x 1024 x 32 bit).
# xc7a200t provides 365 x 18Kb BRAMs, so the 16 KiB footprint fits easily.
set_property BLOCK_SYNTH.RETIMING 1 [current_design]
