# Package bmt_rate (wrapper + unmodified bmt_pregen RTL) as a Vitis RTL kernel.
#
#   vivado -mode batch -source package_kernel.tcl -tclargs <rtl_dir> <xo_path>
#
# -import_files copies the RTL into the IP, so the .xo does not depend on
# <rtl_dir> afterwards.

set rtl_dir [file normalize [lindex $argv 0]]
set xo_path [file normalize [lindex $argv 1]]
set here    [file dirname [file normalize [info script]]]
set part    xcu55c-fsvh2892-2L-e
set work    [file normalize ./build/pack]

# bmt_pregen and everything below it. pilot_switch_top, pilot_pkg, the HMAC
# and SHA files are not needed for this measurement.
set rtl_files {
    bmt_pregen.v
    prng_xoshiro256pp.sv
    aes_gcm_encrypt_24b.v
    aes128_round_fpga.v
    aes128_key_expansion_fpga.v
    aes_func.v
    ghash_single_cycle_fpga.v
}

file delete -force $work
create_project -force pack $work/proj -part $part

add_files -norecurse $here/src/bmt_rate.v
foreach f $rtl_files { add_files -norecurse [file join $rtl_dir $f] }
set_property top bmt_rate [current_fileset]
update_compile_order -fileset sources_1

ipx::package_project -root_dir $work/ip -vendor user.org -library kernel \
    -taxonomy /KernelIP -import_files -set_current false
ipx::unload_core $work/ip/component.xml
ipx::edit_ip_in_project -upgrade true -name edit_ip -directory $work/ip $work/ip/component.xml

set core [ipx::current_core]
set_property core_revision 1 $core
foreach up [ipx::get_user_parameters -of_objects $core] {
    ipx::remove_user_parameter [get_property NAME $up] $core
}

# Usually inferred from the port names already; harmless if so.
catch { ipx::infer_bus_interface interrupt xilinx.com:signal:interrupt_rtl:1.0 $core }
ipx::associate_bus_interfaces -busif m00_axi       -clock ap_clk $core
ipx::associate_bus_interfaces -busif s_axi_control -clock ap_clk $core
catch { ipx::associate_bus_interfaces -clock ap_clk -reset ap_rst_n $core }

set_property sdx_kernel      true $core
set_property sdx_kernel_type rtl  $core
catch { set_property ipi_drc   {ignore_freq_hz true}         $core }
catch { set_property vitis_drc {ctrl_protocol ap_ctrl_hs}    $core }

ipx::create_xgui_files $core
ipx::update_checksums  $core
ipx::check_integrity -kernel $core
ipx::save_core $core
close_project -delete

package_xo -force -xo_path $xo_path -kernel_name bmt_rate \
    -ip_directory $work/ip -kernel_xml $here/kernel.xml
