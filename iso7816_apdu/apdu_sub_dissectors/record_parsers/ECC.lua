-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

local p = Proto.new("iso7816.apdu.record_parsers.ecc", "ECC (Emergency Call Codes):")
local pf = {
    ecc = ProtoField.string(p.name .. ".ecc", "Emergency Call Code"),
    alpha_id = ProtoField.string(p.name .. ".ecc.alpha_id", "Emergency Call Code Alpha Identifier"),
    police = ProtoField.uint8(p.name .. ".ecc.police", "Police", base.HEX, YES_NO, 0x80),
    ambulance = ProtoField.uint8(p.name .. ".ecc.ambulance", "Ambulance", base.HEX, YES_NO, 0x40),
    fire_brigade = ProtoField.uint8(p.name .. ".ecc.fire_brigade", "Fire Brigade", base.HEX, YES_NO, 0x20),
    marine_guard = ProtoField.uint8(p.name .. ".ecc.marine_guard", "Marine Guard", base.HEX, YES_NO, 0x10),
    mountain_rescue = ProtoField.uint8(p.name .. ".ecc.mountain_rescue", "Mountain Rescue", base.HEX, YES_NO, 0x08),
    manuall_ecall = ProtoField.uint8(p.name .. ".ecc.manuall_ecall", "manually initiated eCall", base.HEX, YES_NO, 0x04),
    automatic_ecall = ProtoField.uint8(p.name .. ".ecc.automatic_ecall", "automatically initiated eCall", base.HEX, YES_NO, 0x02),
    unused = ProtoField.uint8(p.name .. ".ecc.unused", "unused", base.HEX, nil, 0x01),
}
p.fields = pf


function p.dissector(buffer, pinfo, tree)
    local len = buffer:len()
    local ecc_f = buffer:range(0, 3)
    local alpha_id_f = buffer:range(3, len-4)
    local category_f = buffer:range(len-1,1)

    local ecc = nibble_swap(ecc_f):gsub('f','')
    local alpha_id = alpha_id_f:string()

    if ecc == '' then
        tree:add(p, buffer, 'empty')
        return buffer:len() -- processed bytes
    end

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer, string.format('%s - %s', ecc, alpha_id))
    subtree:add(pf.ecc, ecc_f, ecc)
    subtree:add(pf.alpha_id, alpha_id_f)
    subtree:add(pf.police, category_f)
    subtree:add(pf.ambulance, category_f)
    subtree:add(pf.fire_brigade, category_f)
    subtree:add(pf.marine_guard, category_f)
    subtree:add(pf.mountain_rescue, category_f)
    subtree:add(pf.manuall_ecall, category_f)
    subtree:add(pf.automatic_ecall, category_f)
    subtree:add(pf.unused, category_f)

    return buffer:len() -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
