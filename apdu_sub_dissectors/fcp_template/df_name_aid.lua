local p = Proto.new("iso7816.apdu.df_name", "DF name (AID)")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    value = ProtoField.bytes(p.name .. ".value", "Value"),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    local length = buffer:len()
    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, length))

    -- Mandatory only for ADF
    -- see (TS 102 221) 11.1.1.4.5 DF name (AID)
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0,1):uint(), buffer(1,1):uint()))
    subtree:add(pf.value, buffer(2, length - 2))

    return length -- processed bytes
end

return p -- returning protocol to add it into dissector table with require