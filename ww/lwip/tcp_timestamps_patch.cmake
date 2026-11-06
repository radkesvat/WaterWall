# Keep timestamp parsing unsigned and reserve the complete padded option before
# segmenting payload. Production timestamp negotiation remains a lwipopts choice.
function(ww_apply_lwip_tcp_timestamps_patch lwip_dir)
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[    mss_local = LWIP_MAX(mss_local, LWIP_TCP_OPT_LEN_TS + 1);]=]
[=[    mss_local = LWIP_MAX(mss_local, optlen + 1);]=])

    # Decode network byte order directly, without signed integer promotion or
    # host-endian assumptions. Each read advances the option cursor separately.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[          tsval = tcp_get_next_optbyte();
          tsval |= (tcp_get_next_optbyte() << 8);
          tsval |= (tcp_get_next_optbyte() << 16);
          tsval |= (tcp_get_next_optbyte() << 24);]=]
[=[          tsval = (u32_t)tcp_get_next_optbyte() << 24;
          tsval |= (u32_t)tcp_get_next_optbyte() << 16;
          tsval |= (u32_t)tcp_get_next_optbyte() << 8;
          tsval |= (u32_t)tcp_get_next_optbyte();]=])
    ww_lwip_replace_all("${lwip_dir}/src/core/tcp_in.c"
[=[pcb->ts_recent = lwip_ntohl(tsval);]=]
[=[pcb->ts_recent = tsval;]=] 2)
endfunction()
