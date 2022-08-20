
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local LIFE_CYCLE_STATUS = {
    [0x00] = 'No information given',
    [0x01] = 'Creation state',
    [0x03] = 'Initialization state',
    [0x05] = 'Operational state - activated',
    [0x07] = 'Operational state - activated',
    [0x04] = 'Operational state - deactivated',
    [0x06] = 'Operational state - deactivated',
    [0x0C] = 'Termination state',
    [0x0D] = 'Termination state',
    [0x0E] = 'Termination state',
    [0x0F] = 'Termination state',
}

local p = Proto.new("iso7816.apdu.life_cycle_status", "Life Cycle Status")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    state = ProtoField.uint8(p.name .. ".byte", "State", base.HEX, LIFE_CYCLE_STATUS),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()),
            string.format('Life Cycle Status: %s', LIFE_CYCLE_STATUS[buffer(2,1):uint()]))

    -- see (TS 102 221) 11.1.1.4.9 Life Cycle Status Integer '8A'
    -- Mandatory
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0,1):uint(), buffer(1,1):uint()))
    subtree:add(pf.state, buffer(2, 1))

    return 3 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
