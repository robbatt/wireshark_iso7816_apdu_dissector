local p = Proto.new("iso7816.apdu.file_descriptor", "File Descriptor")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    byte = ProtoField.uint8(p.name .. ".byte", "Descriptor Byte", base.HEX),
    data_coding = ProtoField.uint8(p.name .. ".data_coding", "Data Coding Byte", base.HEX),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()))

    -- see (TS 102 221) 11.1.1.4.3 File descriptor
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))
    subtree:add(pf.byte, buffer(2, 1))
    subtree:add(pf.data_coding, buffer(3, 1))


    return 4 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
