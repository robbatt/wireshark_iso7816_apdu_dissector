
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

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
local df = 'apdu_sub_dissectors/fcp_template/pin_status/'
local dt = DissectorTable.new('iso7816.apdu.fcp.pin_status', 'ISO7816-APDU fcp template - pin status - sub-dissectors', ftypes.UINT8, base.HEX, p)
dt:add(0x95, require(df .. 'usage_qualifier'))
dt:add(0x83, require(df .. 'key_reference'))

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
    local key_reference_count = 0
    while offset < length do
        local tlv_tag = buffer(offset, 1):uint()
        local tlv_dissector = dt:get_dissector(tlv_tag)
        local tlv_length = 2 + buffer(offset + 1, 1):uint()

        local consumed_bytes = tlv_length
        if tlv_dissector then

            -- workaround to pass the state of this entry, which is defined earlier to the according sub-dissector
            if tlv_tag == 0x83 then -- key reference, enabled info
                pinfo.private.key_reference_enabled = buffer(4, do_length):bitfield(key_reference_count)
                key_reference_count = key_reference_count + 1
            end
            consumed_bytes = tlv_dissector:call(buffer(offset, tlv_length):tvb(), pinfo, tree)
        else
            print(string.format('frame: %s - No tlv-dissector found for tag: 0x%02x in dissector: %s', pinfo.number, tlv_tag, p.name))
        end
        offset = offset + consumed_bytes
    end

    return offset -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
