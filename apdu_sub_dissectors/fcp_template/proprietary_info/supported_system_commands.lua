local SUPPORT = {
    [0x00] = 'TERMINAL CAPABILITY is not supported',
    [0x01] = 'TERMINAL CAPABILITY is supported',
}

local p = Proto.new("iso7816.apdu.proprietary_info.supported_system_commands", "- Supported system commands")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    byte = ProtoField.uint8(p.name .. ".byte", "Supported system commands Byte", base.HEX),
    terminal_capability = ProtoField.uint8(p.name .. ".terminal_capability", "Terminal capability supported?", base.DEC, YES_NO, 0x01),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()))

    -- see (TS 102 221) 11.1.1.4.6.8 - Supported system commands
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%02x, Content: %s byte(s)', buffer(0,1):uint(), buffer(1,1):uint()))
    subtree:add(pf.byte, buffer(2, 1))
    subtree:add(pf.terminal_capability, buffer(2, 1))

    return 3 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
