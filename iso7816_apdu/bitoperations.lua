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

function mcc(buffer)
    if buffer:len() ~= 3 then
        return 0 --'buffer length != 3 byte'
    end

    local mcc_start = BIT.bswap8(buffer:range(0,1):uint())
    local mcc_end = buffer:range(1,1):bitfield(4,4)

    local mcc = string.format('%02x%01x', mcc_start, mcc_end)
    return tonumber(mcc)
end

function mnc(buffer)
    if buffer:len() ~= 3 then
        return 0 -- 'buffer length != 3 byte'
    end

    local mnc_start = BIT.bswap8(buffer:range(2,1):uint())
    local mnc_end = buffer:range(1,1):bitfield(0,4)

    local mnc = string.format('%02x%01x', mnc_start, mnc_end)
    return tonumber(mnc)
end