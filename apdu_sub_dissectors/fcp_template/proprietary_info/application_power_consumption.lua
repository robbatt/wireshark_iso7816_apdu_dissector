local SUPPLY_VOLTAGE_CLASS = {
    -- see (TS 102 221) table 6.1
    [0x01] = 'Supply voltage class A',
    [0x02] = 'Supply voltage class B',
    [0x04] = 'Supply voltage class C',
    [0x08] = 'Supply voltage class D',
}

local p = Proto.new("iso7816.apdu.proprietary_info.application_power_consumption", "- Application Power Consumption")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    voltage_class = ProtoField.uint8(p.name .. ".voltage_class", "Supply Voltage Class", base.HEX, SUPPLY_VOLTAGE_CLASS),
    consumption = ProtoField.string(p.name .. ".consumption", "Application power consumption"),
    frequency = ProtoField.string(p.name .. ".frequency", "Power consumption reference frequency (x0.1)"),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    local consumption = buffer(3, 1):uint() -- consumption in mA (0x01 - 0x3C)
    local frequency = buffer(4, 1):uint() * 0.1 -- frequency * 0.1 MHz - '0A' is 1 MHz - 'FE' is 25,4 MHz (0x0A - 0xFF)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()), string.format('- Application Power Consumption: %s mA at %s MHz', consumption, frequency))

    -- see (TS 102 221) 11.1.1.4.6.2 Application power consumption
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%02x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))

    subtree:add(pf.voltage_class, buffer(2, 1))
    subtree:add(pf.consumption, buffer(3, 1), string.format('(0x%02x) - %s mA', buffer(3, 1):uint(), consumption))
    subtree:add(pf.frequency, buffer(4, 1), string.format('(0x%02x) - %s MHz', buffer(4, 1):uint(), frequency))

    return 5 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
