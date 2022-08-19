SECURITY_ATTRIBUTES = {
    -- TODO The value of the AM_DO and the SC_DO is defined in ISO/IEC 7816-4
    AM_DO = {},
    SC_DO = {}
}

local p = Proto.new("iso7816.apdu.security_attribute.expanded", "Security Attribute (Expanded)")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    am_do_tag = ProtoField.uint8(p.name .. ".am_do.tag", "AM DO Tag", base.HEX, SECURITY_ATTRIBUTES.AM_DO),
    am_do_length = ProtoField.uint8(p.name .. ".am_do.length", "Length"),
    am_do_data = ProtoField.bytes(p.name .. ".am_do.bytes", "bytes"),
    sc_do_tag = ProtoField.uint8(p.name .. ".sc_do.tag", "SC DO Tag", base.HEX, SECURITY_ATTRIBUTES.SC_DO),
    sc_do_length = ProtoField.uint8(p.name .. ".sc_do.length", "Length"),
    sc_do_data = ProtoField.bytes(p.name .. ".sc_do.bytes", "bytes"),

}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    local length = buffer:len()
    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, length))

    -- see (TS 102 221) 11.1.1.4.7 - Security attributes '8B', '8C' or 'AB'
    -- Mandatory, only one shall be present
    -- see (TS 102 221) 11.1.1.4.7.2 - Expanded format 'AB'
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))
    -- TODO test this implementation with live data
    local security_attribute_length = buffer(1, 1):uint()
    local offset = 2

    while offset < security_attribute_length do

        subtree:add(pf.section, buffer(offset, 2), string.format('AM DO Tag: 0x%2x, Content: %s byte(s)', buffer(offset, 1):uint(), buffer(offset + 1, 1):uint()))
        --subtree:add(pf.am_do_tag, buffer(offset, 1))
        --subtree:add(pf.am_do_length, buffer(offset + 1, 1))
        local am_do_length = buffer(offset + 1, 1):uint()
        subtree:add(pf.am_do_data, buffer(offset + 2, am_do_length))
        offset = offset + 2 + am_do_length

        subtree:add(pf.section, buffer(offset, 2), string.format('SC DO Tag: 0x%2x, Content: %s byte(s)', buffer(offset, 1):uint(), buffer(offset + 1, 1):uint()))
        --subtree:add(pf.sc_do_tag, buffer(offset, 1))
        --subtree:add(pf.sc_do_length, buffer(offset + 1, 1))
        local sc_do_length = buffer(offset + 1, 1):uint()
        subtree:add(pf.sc_do_data, buffer(offset + 2, sc_do_length))
        offset = offset + 2 + sc_do_length
    end
    -- TODO test this implementation with live data
    -- TODO interpretation of sc bytes, see ISO/IEC 7816-4: "Identification cards -- Integrated circuit cards -- Part 4: Organization, security and commands for interchange".

    return 2 + security_attribute_length -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
