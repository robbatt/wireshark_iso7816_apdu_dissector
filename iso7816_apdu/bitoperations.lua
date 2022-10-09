-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

local BIT = require('numberlua')

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
