-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

local p = Proto.new("iso7816.apdu.file_parsers.HPPLMN", "HPPLMN (Higher Priority PLMN search period):")
local pf = {
    time_interval = ProtoField.uint8(p.name .. ".time_interval", "Time interval:", base.DEC),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)
    -- optional, add a new level (dropdown) for this section

    local time_interval_f = buffer:range(0,1)
    local time_interval = time_interval_f:uint() * 6

    local subtree = tree:add(p, buffer, string.format('%s minutes',time_interval))
    subtree:add(pf.time_interval, time_interval_f, time_interval, string.format('Time interval: %s minutes',time_interval))

    return buffer:len() -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
