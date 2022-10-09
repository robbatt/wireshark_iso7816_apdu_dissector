-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

local LOCATION_UPDATE_STATUS = {
    [0x00] = 'updated'
}

local p = Proto.new("iso7816.apdu.file_parsers.loci", "LOCI (Location Information):")
local pf = {
    tmsi = ProtoField.uint32(p.name .. ".tmsi", "TMSI", base.HEX),
    --LAI (Location Area Information)
    mcc_mnc = ProtoField.string(p.name .. ".mcc_mnc", "MCC & MNC"),
    lac = ProtoField.uint16(p.name .. ".lac", "LAC", base.HEX),

    rfu = ProtoField.uint8(p.name .. ".rfu", "RFU", base.HEX),
    location_update_status = ProtoField.uint8(p.name .. ".location_update_status", "Location update status", base.HEX, LOCATION_UPDATE_STATUS),
}
p.fields = pf


function p.dissector(buffer, pinfo, tree)
    local tmsi_f = buffer:range(0, 4)
    local mcc_mnc_f = buffer:range(4, 3)
    local lac_f = buffer:range(7, 2) --tonumber( swapped:sub(0, 1) )
    local rfu_f = buffer:range(9, 1)
    local status_f = buffer:range(10, 1)

    local mcc = mcc(mcc_mnc_f)
    local mnc = mnc(mcc_mnc_f)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer, string.format('MCC/MNC: %s/%s', mcc, mnc))
    subtree:add(pf.tmsi, tmsi_f)
    subtree:add(pf.mcc_mnc, mcc_mnc_f, string.format('%s/%s (0x%06x)',mcc, mnc,  mcc_mnc_f:uint()))
    subtree:add(pf.lac, lac_f)
    subtree:add(pf.rfu, rfu_f)
    subtree:add(pf.location_update_status, status_f)

    return buffer:len() -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
