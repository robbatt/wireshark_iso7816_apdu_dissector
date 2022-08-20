
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local p = Proto.new("iso7816.apdu.file_size", "File Size")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    size = ProtoField.string(p.name .. ".size", "Size ", ' bytes (body of EF, or record length of linear fixed or cyclic EF)'),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    local length = buffer:len()
    local file_size_length = buffer(1, 1):uint() -- should be >=2
    local file_size = buffer(2, file_size_length):uint()

    if _G.conversations[pinfo.number] then
        _G.conversations[pinfo.number].expect_read_binary_file_size = file_size -- store this for conversation mapping
        print(string.format('frame: %s - set expect_read_binary_file_size to: %s', pinfo.number, file_size))
    end

    -- see (TS 102 221) 11.1.1.4.1 - File size '80'
    -- Mandatory, only for EF

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, length), string.format('File Size: %s bytes', file_size))

    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))
    subtree:add(pf.size, buffer(2, file_size_length), string.format('%s bytes', file_size))
    return 2 + file_size_length -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
