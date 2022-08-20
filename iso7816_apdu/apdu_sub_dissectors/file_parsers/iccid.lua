
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local BIT = require('numberlua')

local p = Proto.new("iso7816.apdu.proprietary_info.iccid", "ICCID:")
local pf = {
    parsed = ProtoField.string(p.name .. ".parsed", "Parsed value"),
}
p.fields = pf

function nibble_swap(buffer)
    local parsed_val = ''
    local length = buffer:len()
    local offset = 0

    while offset < length do
        local integer16 = buffer(offset, 2):uint()
        local swapped16 = BIT.bswap16(integer16)
        parsed_val = string.format('%s%02x', parsed_val, swapped16)
        offset = offset + 2
    end

    return parsed_val
end

function p.dissector(buffer, pinfo, tree)

    local parsed = nibble_swap(buffer)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer, parsed)
    subtree:add(pf.parsed, parsed)

    return buffer:len() -- processed bytes
end

return p -- returning protocol to add it into dissector table with require