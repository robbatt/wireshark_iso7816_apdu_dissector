-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

local ROUTING_AREA_UPDATE_STATUS = {
    [0] = 'updated',
    [1] = 'not updated',
    [2] = 'PLMN not allowed',
    [3] = 'Location Area not allowed'
}

local p = Proto.new("iso7816.apdu.file_parsers.psloci", "PSLOCI (Packet Switched Location Information):")
local pf = {
    p_tmsi = ProtoField.uint32(p.name .. ".p_tmsi", "P-TMSI", base.HEX),
    p_tmsi_sig = ProtoField.uint24(p.name .. ".p_tmsi_signature", "P-TMSI signature value", base.HEX),
    --LAI (Location Area Information)
    mcc_mnc = ProtoField.string(p.name .. ".mcc_mnc", "MCC & MNC"),
    lac = ProtoField.uint16(p.name .. ".lac", "LAC", base.HEX),

    rac = ProtoField.uint8(p.name .. ".rac", "RAC", base.HEX),
    routing_area_update_status = ProtoField.uint8(p.name .. ".routing_area_update_status", "Routing area update status", base.HEX, ROUTING_AREA_UPDATE_STATUS),
}
p.fields = pf


function p.dissector(buffer, pinfo, tree)
    local p_tmsi_f = buffer:range(0, 4)
    local p_tmsi_sig_f = buffer:range(4, 3)
    local mcc_mnc_f = buffer:range(7, 3)
    local lac_f = buffer:range(10, 2)
    local rac_f = buffer:range(12, 1)
    local status_f = buffer:range(13, 1)

    local mcc = mcc(mcc_mnc_f)
    local mnc = mnc(mcc_mnc_f)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer, string.format('MCC/MNC: %s/%s', mcc, mnc))
    subtree:add(pf.p_tmsi, p_tmsi_f)
    subtree:add(pf.p_tmsi_sig, p_tmsi_sig_f)
    subtree:add(pf.mcc_mnc, mcc_mnc_f, string.format('%s/%s (0x%06x)',mcc, mnc, mcc_mnc_f:uint()))
    subtree:add(pf.lac, lac_f)
    subtree:add(pf.rac, rac_f)
    subtree:add(pf.routing_area_update_status, status_f)

    return buffer:len() -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
