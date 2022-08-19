local FILE_DETAILS = {
    [0x01] = 'DER coding only is supported',
}

local p = Proto.new("iso7816.apdu.proprietary_info.file_details", "- File Details")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    byte = ProtoField.uint8(p.name .. ".byte", "File details Byte", base.HEX),
    file_details = ProtoField.uint8(p.name .. ".file_details", "Details", base.HEX, FILE_DETAILS, 0x01),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()))

    -- see (TS 102 221) 11.1.1.4.6.5 - File details
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%02x, Content: %s byte(s)', buffer(0,1):uint(), buffer(1,1):uint()))
    subtree:add(pf.byte, buffer(2, 1))
    subtree:add(pf.file_details, buffer(2, 1))


    return 3 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
