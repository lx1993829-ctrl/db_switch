# Build the bmt_rate kernel (.xo -> .xclbin) and its host program.
#
#   make xclbin      package + link (needs Vivado/Vitis, hours)
#   make host        host program (needs XRT + OpenSSL headers)
#   make run         run on the card
#
# Override on the command line, e.g.  make xclbin FREQ=250 MCP=0

PLATFORM ?= xilinx_u55c_gen3x16_xdma_3_202210_1
RTL_DIR  ?= /mnt/e/db_switch/rtl
FREQ     ?= 300          # requested kernel clock, MHz (Vitis scales it down if timing fails)
MCP      ?= 1            # 1: apply the key-schedule multicycle exception (key_schedule_mcp.tcl)
DEVICE   ?= 0            # card index or BDF for `make run`
CYCLES   ?= 1000000000
RUNS     ?= 3

XILINX_XRT ?= /opt/xilinx/xrt

BUILD  := build
XO     := $(BUILD)/bmt_rate.xo
XCLBIN := $(BUILD)/bmt_rate.xclbin
HOST   := bmt_rate.exe

RTL_FILES := $(addprefix $(RTL_DIR)/,bmt_pregen.v prng_xoshiro256pp.sv aes_gcm_encrypt_24b.v \
             aes128_round_fpga.v aes128_key_expansion_fpga.v aes_func.v ghash_single_cycle_fpga.v)

ifeq ($(strip $(MCP)),1)
VPP_MCP := --vivado.prop run.impl_1.STEPS.OPT_DESIGN.TCL.PRE=$(CURDIR)/key_schedule_mcp.tcl
endif

.PHONY: all xo xclbin host run clean
all: host xclbin

xo: $(XO)
xclbin: $(XCLBIN)
host: $(HOST)

$(XO): src/bmt_rate.v kernel.xml package_kernel.tcl $(RTL_FILES)
	mkdir -p $(BUILD)
	vivado -mode batch -nojournal -log $(BUILD)/package.log -source package_kernel.tcl \
	    -tclargs $(RTL_DIR) $@

$(XCLBIN): $(XO) link.cfg key_schedule_mcp.tcl
	v++ -l -t hw --platform $(PLATFORM) --config link.cfg \
	    --kernel_frequency $(strip $(FREQ)) $(VPP_MCP) \
	    --temp_dir $(BUILD)/_x --report_dir $(BUILD)/reports --log_dir $(BUILD)/logs \
	    -o $@ $<

$(HOST): host/host.cpp
	g++ -std=c++17 -O2 -Wall -I$(XILINX_XRT)/include -o $@ $< \
	    -L$(XILINX_XRT)/lib -lxrt_coreutil -lcrypto -pthread

run: $(HOST)
	./$(HOST) -x $(XCLBIN) -d $(DEVICE) --cycles $(CYCLES) --runs $(RUNS)

clean:
	rm -rf $(BUILD) $(HOST) .Xil *.log *.jou
