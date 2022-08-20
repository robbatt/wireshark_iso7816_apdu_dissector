
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local CLOCK_STOP = {
    [0x01] = 'No preferred level',
    [0x03] = 'High level preferred',
    [0x05] = 'Low level preferred',
    [0x07] = 'RFU',
    [0x00] = 'Never',
    [0x02] = 'Unless at high level',
    [0x04] = 'Unless at low level',
    [0x06] = 'RFU',
}

local p = Proto.new("iso7816.apdu.proprietary_info.uicc_characteristics", "- UICC Characteristics")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    byte = ProtoField.uint8(p.name .. ".byte", "UICC characteristics Byte", base.HEX),
    clock_stop_allowed = ProtoField.uint8(p.name .. ".clock_stop_allowed", "Clock stop allowed", base.DEC, YES_NO, 0x01),
    clock_stop = ProtoField.uint8(p.name .. ".clock_stop", "Clock stop", base.DEC, CLOCK_STOP, 0x0D),
    supply_voltage_class_a = ProtoField.uint8(p.name .. ".supply_voltage_class_a", "Supply voltage class A", base.DEC, YES_NO, 0x10),
    supply_voltage_class_b = ProtoField.uint8(p.name .. ".supply_voltage_class_b", "Supply voltage class B", base.DEC, YES_NO, 0x20),
    supply_voltage_class_c = ProtoField.uint8(p.name .. ".supply_voltage_class_c", "Supply voltage class C", base.DEC, YES_NO, 0x40),
    supply_voltage_class_d = ProtoField.uint8(p.name .. ".supply_voltage_class_d", "Supply voltage class D", base.DEC, YES_NO, 0x80),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()))

    -- see (TS 102 221) 11.1.1.4.6.1 UICC characteristics
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%02x, Content: %s byte(s)', buffer(0,1):uint(), buffer(1,1):uint()))
    subtree:add(pf.byte, buffer(2, 1))
    subtree:add(pf.clock_stop_allowed, buffer(2, 1))
    subtree:add(pf.clock_stop, buffer(2, 1))
    subtree:add(pf.supply_voltage_class_a, buffer(2, 1))
    subtree:add(pf.supply_voltage_class_b, buffer(2, 1))
    subtree:add(pf.supply_voltage_class_c, buffer(2, 1))
    subtree:add(pf.supply_voltage_class_d, buffer(2, 1))

    return 3 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
