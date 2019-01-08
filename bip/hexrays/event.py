
import ida_hexrays

class HexRaysEvent(object):
    """
        Enum object for the hexrays event. This is documented in
        https://www.hex-rays.com/products/decompiler/manual/sdk/hexrays_8hpp.shtml 
        https://www.hex-rays.com/products/decompiler/manual/sdk/hexrays_8hpp_source.shtml
        and defined in ``ida_hexrays`` python file.

        .. todo:: doc this enum

        .. todo:: make wrapper on functions and stuff

    """
    hxe_flowchart               = ida_hexrays.hxe_flowchart
    hxe_stkpnts                 = ida_hexrays.hxe_stkpnts
    hxe_prolog                  = ida_hexrays.hxe_prolog
    hxe_microcode               = ida_hexrays.hxe_microcode
    hxe_preoptimized            = ida_hexrays.hxe_preoptimized
    hxe_locopt                  = ida_hexrays.hxe_locopt
    hxe_prealloc                = ida_hexrays.hxe_prealloc
    hxe_glbopt                  = ida_hexrays.hxe_glbopt
    hxe_structural              = ida_hexrays.hxe_structural
    hxe_maturity                = ida_hexrays.hxe_maturity
    hxe_interr                  = ida_hexrays.hxe_interr
    hxe_combine                 = ida_hexrays.hxe_combine
    hxe_print_func              = ida_hexrays.hxe_print_func
    hxe_func_printed            = ida_hexrays.hxe_func_printed
    hxe_resolve_stkaddrs        = ida_hexrays.hxe_resolve_stkaddrs
    hxe_open_pseudocode         = ida_hexrays.hxe_open_pseudocode # 100
    hxe_switch_pseudocode       = ida_hexrays.hxe_switch_pseudocode
    hxe_refresh_pseudocode      = ida_hexrays.hxe_refresh_pseudocode
    hxe_close_pseudocode        = ida_hexrays.hxe_close_pseudocode
    hxe_keyboard                = ida_hexrays.hxe_keyboard
    hxe_right_click             = ida_hexrays.hxe_right_click
    hxe_double_click            = ida_hexrays.hxe_double_click
    hxe_curpos                  = ida_hexrays.hxe_curpos
    hxe_create_hint             = ida_hexrays.hxe_create_hint
    hxe_text_ready              = ida_hexrays.hxe_text_ready
    hxe_populating_popup        = ida_hexrays.hxe_populating_popup
    lxe_lvar_name_changed       = ida_hexrays.lxe_lvar_name_changed
    lxe_lvar_type_changed       = ida_hexrays.lxe_lvar_type_changed
    lxe_lvar_cmt_changed        = ida_hexrays.lxe_lvar_cmt_changed
    lxe_lvar_mapping_changed    = ida_hexrays.lxe_lvar_mapping_changed
    USE_KEYBOARD                = ida_hexrays.USE_KEYBOARD
    USE_MOUSE                   = ida_hexrays.USE_MOUSE






