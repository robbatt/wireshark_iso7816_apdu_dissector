-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

local TON = {
    [0xf] = 'reserved for extension'
}
local RECORD_IDENTIFIER = {
    [0xff] = 'Not used'
}

local p = Proto.new("iso7816.apdu.record_parsers.msisdn", "MSISDN:")
local pf = {
    alpha_id = ProtoField.string(p.name .. ".msisdn.alpha_id", "Alpha Identifier"),
    bcd_scc_length = ProtoField.uint8(p.name .. ".msisdn.bcd_scc_length", "Length of BCD number / SSC contents"),
    ton_and_npi = ProtoField.uint8(p.name .. ".msisdn.ton_and_npi", "TON and NPI"),
    ton = ProtoField.uint8(p.name .. ".msisdn.ton", "TON", base.HEX, TON, 0xf0),
    npi = ProtoField.uint8(p.name .. ".msisdn.npi", "NPI", base.HEX, nil, 0x0f),
    dialing_number = ProtoField.string(p.name .. ".msisdn.dialling_number", "Dialing Number/SCC String"),
    capability = ProtoField.uint8(p.name .. ".msisdn.capability", "Capability/Configuration Identifier", base.DEC),
    extension = ProtoField.uint8(p.name .. ".msisdn.extension", "Extension5 Record Identifier", base.HEX, RECORD_IDENTIFIER),
    --unused = ProtoField.uint8(p.name .. ".msisdn.unused", "unused", base.HEX, nil, 0x01),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)
    --from 31 x ff

    --Alpha Identifier
    --Length of BCD number/SSC contents  255
    --TON and NPI
    --Type of Number  reserved for extension
    --Numbering plan identification  1111b
    --Dialling Number/SSC String
    --Capability/Configuration Identifier  255
    --Extension 5 Record Identifier  Not used

    local len = buffer:len()
    local alpha_len = len - 14
    local alpha_id_f = buffer:range(0, alpha_len)
    local bcd_scc_length_f = buffer:range(alpha_len,1)
    local ton_and_npi_f = buffer:range(alpha_len + 1,1)
    local dialing_number_f = buffer:range(alpha_len + 2,10)
    local capability_f = buffer:range(alpha_len + 12, 1)
    local extension_f = buffer:range(alpha_len + 13, 1)

    local alpha_id = alpha_id_f:string()--:gsub('f', '')

    --if alpha_id == '' then
    --    tree:add(p, buffer, 'empty')
    --    return buffer:len() -- processed bytes
    --end

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer, string.format('WORK IN PROGRESS -- %s', alpha_id))
    subtree:add(pf.alpha_id, alpha_id)
    subtree:add(pf.bcd_scc_length, bcd_scc_length_f)
    subtree:add(pf.ton_and_npi, ton_and_npi_f)
    subtree:add(pf.ton, ton_and_npi_f)
    subtree:add(pf.npi, ton_and_npi_f)
    subtree:add(pf.dialing_number, dialing_number_f)
    subtree:add(pf.capability, capability_f)
    subtree:add(pf.extension, extension_f)


    return buffer:len() -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
