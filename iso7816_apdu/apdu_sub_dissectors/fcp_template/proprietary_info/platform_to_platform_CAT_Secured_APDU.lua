
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local p = Proto.new("iso7816.apdu.proprietary_info.platform_to_platform_CAT_Secured_APDU", "- Platform to Platform CAT Secured APDU")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    byte = ProtoField.uint8(p.name .. ".byte", "Platform to Platform CAT Secured APDU", base.HEX),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()))

    -- see (TS 102 221) 11.1.1.4.6.10 Platform to Platform CAT Secured APDU
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%02x, Content: %s byte(s)', buffer(0,1):uint(), buffer(1,1):uint()))
    subtree:add(pf.byte, buffer(2, 1))
    return 3 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
