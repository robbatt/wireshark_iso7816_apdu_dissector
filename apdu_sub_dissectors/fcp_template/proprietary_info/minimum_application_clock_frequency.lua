local p = Proto.new("iso7816.apdu.proprietary_info.min_application_clock_frequency", "- Minimum application clock frequency")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    frequency = ProtoField.string(p.name .. ".frequency", "Application minimum clock frequency (x0.1)"),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    local frequency = buffer(2, 1):uint() * 0.1 -- frequency * 0.1 MHz - '0A' is 1 MHz - 'FE' is 25,4 MHz (0x0A - 0xFF)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()), string.format('- Minimum application clock frequency: %s MHz', frequency))

    -- see (TS 102 221) 11.1.1.4.6.3 Minimum application clock frequency
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%02x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))
    subtree:add(pf.frequency, buffer(2, 1), string.format('(0x%02x) - %s MHz', buffer(2, 1):uint(), frequency))

    return 3 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
