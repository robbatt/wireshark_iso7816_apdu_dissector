local USAGE_QUALIFIER = {
    [0x00] = 'verification requirement not used', -- 'the verification requirement is not used for verification',
    [0x80] = 'verification (DST, CCT), encipherment (CT), external authentication (AT)',
    [0x40] = 'computation (DST, CCT), decipherment (CT), internal authentication (AT)',
    [0x20] = 'SM response (CCT, CT, DST)',
    [0x10] = 'SM command (CCT, CT, DST)',
    [0x08] = 'PIN for verification', -- (Key Reference data user knowledge based)
    [0x04] = 'user authentication, biometric based',
}

local p = Proto.new("iso7816.apdu.pin_status.usage_qualifier", "- Usage Qualifier")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    byte = ProtoField.uint8(p.name .. ".byte", "Usage Qualifier Byte", base.HEX),
    usage_qualifier = ProtoField.uint8(p.name .. ".usage_qualifier", "Usage Qualifier", base.DEC, USAGE_QUALIFIER, 0xFF),
}
p.fields = pf

function p.dissector(buffer, packageInfo, tree)

    local usage_qualifier = buffer(2, 1):uint()
    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len(), string.format('- Usage Qualifier: %s ', USAGE_QUALIFIER[usage_qualifier])))

    -- see (TS 102 221) 11.1.1.4.6.1 UICC characteristics
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%02x, Content: %s byte(s)', buffer(0,1):uint(), buffer(1,1):uint()))
    subtree:add(pf.byte, buffer(2, 1))
    subtree:add(pf.usage_qualifier, buffer(2, 1))


    return 3 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
