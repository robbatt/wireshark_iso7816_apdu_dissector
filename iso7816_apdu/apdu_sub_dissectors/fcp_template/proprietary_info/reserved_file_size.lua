
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local p = Proto.new("iso7816.apdu.proprietary_info.reserved_file_size", "- Reserved File Size")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    size = ProtoField.string(p.name .. ".size", "Reserved File Size"),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    local length = buffer:len()
    local size = buffer(2, length - 2):uint() -- Reserved File Size in bytes

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()), string.format('- Reserved File Size: %s bytes', size))

    -- see (TS 102 221) 11.1.1.4.6.6 - Reserved File Size
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%02x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))
    subtree:add(pf.size, buffer(2, length - 2), string.format('(0x%02x) - %s bytes', buffer(2, length - 2):uint(), size))

    return length -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
