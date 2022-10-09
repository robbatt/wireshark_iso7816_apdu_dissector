
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local p = Proto.new("iso7816.apdu.file_parsers.iccid", "ICCID:")
local pf = {
    parsed = ProtoField.string(p.name .. ".parsed", "ICCID"),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    local parsed = nibble_swap(buffer)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer, parsed)
    subtree:add(pf.parsed, parsed)

    return buffer:len() -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
