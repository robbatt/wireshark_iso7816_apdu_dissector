local p = Proto.new("iso7816.apdu.pin_status", "PIN Status")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    do_section = ProtoField.string(p.name .. ".do", "Data Object  "),
    do_data = ProtoField.bytes(p.name .. ".do.data", "Data"),

    uq_section = ProtoField.string(p.name .. ".usage_qualifier", "Usage Qualifier"),
    usage_qualifier_data = ProtoField.bytes(p.name .. ".usage_qualifier.data", "Data"),

    key_reference_section = ProtoField.string(p.name .. ".key_reference", "Key Reference"),
    key_reference_data = ProtoField.uint8(p.name .. ".key_reference.data", "Data", base.HEX),

}
p.fields = pf

local dt = DissectorTable.new('iso7816.apdu.fcp.pin_status', 'ISO7816-APDU fcp template - pin status - sub-dissectors', ftypes.UINT8, base.HEX, p)
dt:add(0x95, require('apdu_sub_dissectors/fcp_template/pin_status/usage_qualifier'))
dt:add(0x83, require('apdu_sub_dissectors/fcp_template/pin_status/key_reference'))

function p.dissector(buffer, pinfo, tree)

    local length = buffer:len()
    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, length))

    -- see (TS 102 221) 11.1.1.4.10 - PIN Status Template DO 'C6'
    -- Mandatory
    subtree:add(pf.section, buffer(0, 3), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))

    local do_length = buffer(3, 1):uint()
    subtree:add(pf.do_section, buffer(2, 3), string.format('Tag: 0x%02x, Content: %s byte(s), Data: 0x%02x', buffer(2, 1):uint(), buffer(3, 1):uint(), buffer(4, do_length):uint()))
    local offset = 4 + do_length

    -- this will call the according sub-dissector for each section
    offset = offset + dissect_remaining_tlvs(buffer(offset):tvb(), pinfo, tree, p, dt)

    return offset -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
