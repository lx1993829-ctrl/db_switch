# Multicycle exception for the AES key schedule (runs before opt_design).
#
# aes128_key_expansion_fpga is combinational: u_gcm/key_r -> all 11 round
# keys -> u_aes/rk*_reg, about 9.2 ns (comment in aes128_round_fpga.v). Left as
# a single-cycle path it caps the kernel clock near 100 MHz.
#
# It is a true multicycle path. aes_gcm_encrypt_24b loads key_r only in
# ST_IDLE on `start`, then spends 4 cycles in ST_INIT_WAIT and 1 in
# ST_SEND_H before the first valid_in; rk0 is first used 6 edges after key_r
# changes, rk_k at 6+k. key_r does not change again until `done`, when the
# AES pipeline is empty. A 4-cycle setup / 3-cycle hold window is inside that.
#
# The host check (GCM tags + c = a & b) would catch a wrong exception.

set src [get_cells -quiet -hierarchical -filter {NAME =~ */u_bmt/u_gcm/key_r_reg*}]
set dst [get_cells -quiet -hierarchical -filter {NAME =~ */u_bmt/u_gcm/u_aes/rk*_reg*}]
puts "key_schedule_mcp: [llength $src] source cells, [llength $dst] destination cells"
if {[llength $src] > 0 && [llength $dst] > 0} {
    set_multicycle_path -setup 4 -from $src -to $dst
    set_multicycle_path -hold  3 -from $src -to $dst
} else {
    puts "CRITICAL WARNING: key_schedule_mcp: cells not found, no multicycle applied"
}
