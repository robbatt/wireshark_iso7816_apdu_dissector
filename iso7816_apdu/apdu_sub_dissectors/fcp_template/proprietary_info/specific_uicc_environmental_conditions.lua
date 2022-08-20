
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local TEMPERATURE_CLASS = {
    [0x00] = 'Standard temperature range',
    [0x01] = 'Temperature class A',
    [0x02] = 'Temperature class B',
    [0x03] = 'Temperature class C',
    [0x04] = 'RFU',
}

local p = Proto.new("iso7816.apdu.proprietary_info.specific_uicc_environmental_conditions", "- Specific UICC Environmental Conditions")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    byte = ProtoField.uint8(p.name .. ".byte", "UICC characteristics Byte", base.HEX),
    temperature_class = ProtoField.uint8(p.name .. ".temperature_class", "Temperature class", base.DEC, TEMPERATURE_CLASS, 0x07),
    high_humidity = ProtoField.uint8(p.name .. ".high_humidity_support", "High humidity supported?", base.DEC, YES_NO, 0x08),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()))

    -- see (TS 102 221) 11.1.1.4.6.9 - Specific UICC environmental conditions
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%02x, Content: %s byte(s)', buffer(0,1):uint(), buffer(1,1):uint()))
    subtree:add(pf.byte, buffer(2, 1))
    subtree:add(pf.temperature_class, buffer(2, 1))
    subtree:add(pf.high_humidity, buffer(2, 1))

    return 3 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
