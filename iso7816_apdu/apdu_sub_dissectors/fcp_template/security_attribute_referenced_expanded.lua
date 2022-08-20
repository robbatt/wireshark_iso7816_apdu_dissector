
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local p = Proto.new("iso7816.apdu.security_attribute.referenced_to_expanded", "Security Attribute (File Reference)")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    EF_ARR_FID = ProtoField.uint8(p.name .. ".ef_arr_fid", "EF ARR File", base.HEX, FILE_IDENTIFIERS),
    SEID = ProtoField.bytes(p.name .. ".seid", "SEID"),
    EF_ARR_Record = ProtoField.bytes(p.name .. ".ef_arr_record", "EF ARR Record"),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    local length = buffer:len()
    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, length))

    -- see (TS 102 221) 11.1.1.4.7 - Security attributes '8B', '8C' or 'AB'
    -- Mandatory, only one shall be present
    -- see (TS 102 221) 11.1.1.4.7.3 - Referenced to expanded format '8B'
    -- TODO implementation of security attribute 8B - Referenced to expanded format
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))

    local security_attribute_length = buffer(1, 1):uint()
    local offset = 2
    if security_attribute_length == 3 then
        subtree:add(pf.EF_ARR_FID, buffer(2, 2))
        subtree:add(pf.EF_ARR_Record, buffer(4, 1))
        offset = offset + 3 -- processed bytes
    elseif security_attribute_length % 2 == 0 then
        subtree:add(pf.EF_ARR_FID, buffer(2, 2))
        offset = offset + 2
        while offset < length do
            subtree:add(pf.SEID, buffer(offset, 1))
            subtree:add(pf.EF_ARR_Record, buffer(offset + 1, 1))
            offset = offset + 2
        end
    end

    -- TODO test this implementation with live data

    return offset -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
