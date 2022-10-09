-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

local EPS_UPDATE_STATUS = {
    [0x00] = 'reserved'
}

local p = Proto.new("iso7816.apdu.file_parsers.epsloci", "EPSLOCI (EPS Location Information):")
local pf = {
    gtui = ProtoField.bytes(p.name .. ".gtui", "Globally Unique Temporary Identifier (GUTI)", base.SPACE),
    tai = ProtoField.bytes(p.name .. ".tai", "Last visited registered Tracking Area Identity (TAI)", base.SPACE),
    eps_update_status = ProtoField.uint8(p.name .. ".eps_update_status", "EPS Update status", base.HEX, EPS_UPDATE_STATUS),
}
p.fields = pf


function p.dissector(buffer, pinfo, tree)
    -- from: 0bf6130184fa989ec851e4bf 1301849b02 00

    -- Globally Unique Temporary Identifier (GUTI)  '0B F6 13 01 84 FA 98 9E C8 51 E4 BF'
    -- 	 	Last visited registered Tracking Area Identity (TAI)  '13 01 84 9B 02'
    -- 	 	EPS Update Status  reserved

    local gtui_f = buffer:range(0, 12)
    local tai_f = buffer:range(12, 5)
    local status_f = buffer:range(17, 1)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer)
    subtree:add(pf.gtui, gtui_f)
    subtree:add(pf.tai, tai_f)
    subtree:add(pf.eps_update_status, status_f)

    return buffer:len() -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
