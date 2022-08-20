
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local KEY_REFERENCE = {
    [0x01] = 'PIN Appl 1',
    [0x02] = 'PIN Appl 2',
    [0x03] = 'PIN Appl 3',
    [0x04] = 'PIN Appl 4',
    [0x05] = 'PIN Appl 5',
    [0x06] = 'PIN Appl 6',
    [0x07] = 'PIN Appl 7',
    [0x08] = 'PIN Appl 8',
    [0x09] = 'RFU',
    [0x0a] = 'ADM1',
    [0x0b] = 'ADM2',
    [0x0c] = 'ADM3',
    [0x0d] = 'ADM4',
    [0x0e] = 'ADM5',

    [0x11] = 'PIN Universal PIN',
    [0x12] = 'RFU (Global)',
    [0x13] = 'RFU (Global)',
    [0x14] = 'RFU (Global)',
    [0x15] = 'RFU (Global)',
    [0x16] = 'RFU (Global)',
    [0x17] = 'RFU (Global)',
    [0x18] = 'RFU (Global)',
    [0x19] = 'RFU (Global)',
    [0x1a] = 'RFU (Global)',
    [0x1b] = 'RFU (Global)',
    [0x1c] = 'RFU (Global)',
    [0x1d] = 'RFU (Global)',
    [0x1e] = 'RFU (Global)',

    [0x81] = 'Second PIN Appl 1',
    [0x82] = 'Second PIN Appl 2',
    [0x83] = 'Second PIN Appl 3',
    [0x84] = 'Second PIN Appl 4',
    [0x85] = 'Second PIN Appl 5',
    [0x86] = 'Second PIN Appl 6',
    [0x87] = 'Second PIN Appl 7',
    [0x88] = 'Second PIN Appl 8',
    [0x89] = 'RFU',
    [0x8a] = 'ADM6',
    [0x8b] = 'ADM7',
    [0x8c] = 'ADM8',
    [0x8d] = 'ADM9',
    [0x8e] = 'ADM10',

    [0x90] = 'RFU (Local)',
    [0x91] = 'RFU (Local)',
    [0x92] = 'RFU (Local)',
    [0x93] = 'RFU (Local)',
    [0x94] = 'RFU (Local)',
    [0x95] = 'RFU (Local)',
    [0x96] = 'RFU (Local)',
    [0x97] = 'RFU (Local)',
    [0x98] = 'RFU (Local)',
    [0x99] = 'RFU (Local)',
    [0x9a] = 'RFU (Local)',
    [0x9b] = 'RFU (Local)',
    [0x9c] = 'RFU (Local)',
    [0x9d] = 'RFU (Local)',
    [0x9e] = 'RFU (Local)',
}
local ENABLED = { ['0'] = 'disabled', ['1'] = 'enabled' }
local p = Proto.new("iso7816.apdu.pin_status.key_reference", "- Key Reference")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    key_reference = ProtoField.uint8(p.name .. ".key_reference", "Key Reference", base.HEX, KEY_REFERENCE),
}
p.fields = pf

function p.dissector(buffer, packageInfo, tree)

    local key_reference = buffer(2, 1):uint()
    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()), string.format('- Key Reference: (0x%02x) - %s - %s', key_reference, KEY_REFERENCE[key_reference], ENABLED[packageInfo.private.key_reference_enabled]))

    -- see (TS 102 221) 11.1.1.4.6.1 UICC characteristics
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%02x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))
    subtree:add(pf.key_reference, buffer(2, 1))

    return 3 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
