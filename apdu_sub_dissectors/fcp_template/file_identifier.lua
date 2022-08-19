local p = Proto.new("iso7816.apdu.file_identifier", "File Identifier (FID)")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    fid = ProtoField.uint8(p.name .. ".fid", "File identifier (FID)", base.HEX, FILE_IDENTIFIERS),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()),string.format('File Identifier (FID): (0x%02x) - %s',buffer(2,2):uint(), FILE_IDENTIFIERS[buffer(2,2):uint()] ))

    -- Mandatory for DF/MF, Optional for ADF
    -- see (TS 102 221) 11.1.1.4.4 File identifier
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0,1):uint(), buffer(1,1):uint()))
    subtree:add(pf.fid, buffer(2, 2))

    return 4 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
