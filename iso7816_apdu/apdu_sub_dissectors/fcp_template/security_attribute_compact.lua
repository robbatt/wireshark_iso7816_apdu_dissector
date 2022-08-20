
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local p = Proto.new("iso7816.apdu.security_attribute.compact", "Security Attribute (Compact)")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    am_byte = ProtoField.bytes(p.name .. ".am_byte", "AM byte"),
    sc_bytes = ProtoField.bytes(p.name .. ".sc_bytes", "SC bytes"),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    local length = buffer:len()
    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, length))

    -- see (TS 102 221) 11.1.1.4.7 - Security attributes '8B', '8C' or 'AB'
    -- Mandatory, only one shall be present
    -- see (TS 102 221) 11.1.1.4.7.1 - Compact format '8C'
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))
    local security_attribute_length = buffer(2, 1):uint()
    subtree:add(pf.am_byte, buffer(2, 1))
    subtree:add(pf.sc_bytes, buffer(3, security_attribute_length))

    -- TODO test this implementation with live data
    -- TODO interpretation of sc bytes, see ISO/IEC 7816-4: "Identification cards -- Integrated circuit cards -- Part 4: Organization, security and commands for interchange".

    return 3 + security_attribute_length -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
