
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local p = Proto.new("iso7816.apdu.short_file_identifier", "Short File Identifier (SFI)")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    sfi = ProtoField.uint8(p.name .. ".sfi", "Short File identifier (SFI)", base.HEX, FILE_IDENTIFIERS, 0xf8),
    unused = ProtoField.uint8(p.name .. ".unused", "Unused", base.HEX, nil, 0x07),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    local length = buffer:len()

    -- see (TS 102 221) 11.1.1.4.8 Short file identifier (SFI)
    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, length))

    if length == 1 then
        -- in this case SFI value is the 5 least significant bits (bits b5 to b1) of the file identifier.
        subtree:add(pf.section, buffer(0, 1), string.format('Tag: 0x%2x, Content: none', buffer(0, 1):uint()))
        return 1 -- processed bytes
    elseif buffer(1, 1):uint() == 0 then
        -- If the TLV is present but empty (i.e. length is 0), the SFI is not supported for the selected file.
        subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s) - SFI not supported', buffer(0, 1):uint(), buffer(1, 1):uint()))
        return 2 -- processed bytes
    else
        subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))
        subtree:add(pf.sfi, buffer(2, 1))
        subtree:add(pf.unused, buffer(2, 1))
        return 3 -- processed bytes
        --NOTE:
        --If the SFI value is identical to the 5 least significant bits of the file identifier then it is implementation
        --dependent if the TLV is not present or if the SFI value is indicated in the TLV.
    end
end

return p -- returning protocol to add it into dissector table with require
