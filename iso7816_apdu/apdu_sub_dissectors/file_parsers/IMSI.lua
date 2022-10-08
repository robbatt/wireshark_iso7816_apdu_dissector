
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local BIT = require('numberlua')

local p = Proto.new("iso7816.apdu.file_parsers.imsi", "IMSI:")
local pf = {
    length = ProtoField.uint8(p.name .. ".length", "Length", base.DEC),
    check_digit = ProtoField.uint8(p.name .. ".check_digit", "Check Digit", base.DEC),
    parsed = ProtoField.string(p.name .. ".parsed", "IMSI"),
}
p.fields = pf

function nibble_swap(buffer)
    local parsed_val = ''
    local length = buffer:len()
    local offset = 0

    while offset < length do
        local integer8 = buffer(offset, 1):uint()
        local swapped8 = BIT.bswap8(integer8)
        parsed_val = string.format('%s%02x', parsed_val, swapped8)
        offset = offset + 1
    end

    return parsed_val
end

function p.dissector(buffer, pinfo, tree)
    local le_f =  buffer:range(0,1)
    local data_f = buffer:range(1)
    local swapped = nibble_swap(data_f)
    local check_digit = tonumber( swapped:sub(0, 1) )
    local parsed = swapped:sub(2)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer, parsed)
    subtree:add(pf.length, le_f)
    subtree:add(pf.check_digit, data_f, check_digit)
    subtree:add(pf.parsed, data_f, parsed)

    return buffer:len() -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
