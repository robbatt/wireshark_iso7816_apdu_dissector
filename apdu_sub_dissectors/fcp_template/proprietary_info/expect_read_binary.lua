local p = Proto.new("iso7816.apdu.proprietary_info.expect_read_binary", "- Expect Read Binary")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    read_offset = ProtoField.uint8(p.name .. ".offset", "Read offset", base.DEC),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    local read_offset_len = buffer(1, 1):uint()
    local read_offset = buffer(2, read_offset_len):uint()

    if _G.conversations[pinfo.number] then
        _G.conversations[pinfo.number].expect_read_binary_offset = read_offset -- store this for conversation mapping
        print(string.format('frame: %s - set expect_read_binary_offset to: %s', pinfo.number, read_offset))
    end


    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()), string.format('- Expect Read Binary from offset: 0x%02x', read_offset))

    -- see (TS 102 221) 11.1.1.4.6.5 - File details
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%02x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))
    subtree:add(pf.read_offset, read_offset)

    return 2 + read_offset_len -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
