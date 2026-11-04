# bmt_rate: BMT triple generation rate on the U55C

Wraps `bmt_pregen` (unmodified, read from `RTL_DIR`) as a Vitis RTL kernel.
The kernel drains both share FIFOs every cycle, so the generator never stalls,
and counts triples and cycles in hardware. The host reads the counters and
decrypts the first 4 triples to confirm the card is producing real ones.

## Files

| File | Purpose |
|---|---|
| `src/bmt_rate.v` | Kernel: AXI-Lite control (ap_ctrl_hs), seed, counters, result write on `m00_axi` |
| `kernel.xml` | Kernel arguments and register offsets for `package_xo` |
| `package_kernel.tcl` | Packages wrapper + 7 RTL files as `bmt_rate.xo` |
| `link.cfg` | One compute unit, `m00_axi` on HBM[0] |
| `key_schedule_mcp.tcl` | Multicycle exception for the combinational AES key schedule (why it is safe: see the file) |
| `host/host.cpp` | XRT host program |
| `Makefile` | Build and run |

## Build (machine with Vitis + the U55C platform installed)

    source /tools/Xilinx/Vitis/<ver>/settings64.sh
    source /opt/xilinx/xrt/setup.sh
    make xclbin RTL_DIR=/path/to/db_switch/rtl      # FREQ=300 MCP=1 by default
    make host

Check the clock Vitis actually achieved (it scales down if timing fails):
`build/reports/link/imp/impl_1_*timing_summary*` and the v++ log.

## Run (host with the card, XRT installed)

    xbutil examine                       # find the card's BDF
    ./bmt_rate.exe -x build/bmt_rate.xclbin -d <BDF> --cycles 1000000000 --runs 3

Options: `--mhz F` uses F as the kernel clock instead of estimating it from
wall time; `--key0/--key1` must match `AES_KEY_S0/S1` in `src/bmt_rate.v`.

## Output

- **cycles / triple (steady state):** clock-independent rate of the RTL.
- **throughput:** triples/s. One triple = one encrypted share for each server.
  A 64-triple response pops 64 entries from one server's FIFO.
- **triple check:** GCM tag verifies with the right key and fails with the
  other one, `(a0^a1) & (b0^b1) == c0^c1`, and no repeated IVs. FAIL here means
  the throughput number is not trustworthy (e.g. a timing problem on the card).

Exit code 0 = all runs PASS.
