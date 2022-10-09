-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

local p = Proto.new("iso7816.apdu.file_parsers.OPLMNwAcT", "OPLMNwAcT (Operator controlled PLMN selector with Access Technology):")
local pf = {
    mcc_mnc = ProtoField.string(p.name .. ".mcc_mnc", "MCC & MNC"),
    ati = ProtoField.uint16(p.name .. ".ati", "ATI", base.HEX),
}
p.fields = pf


function p.dissector(buffer, pinfo, tree)
    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer)

    for i=0,buffer:len() - 1,5 do
        local plmn_f = buffer:range(i,3)
        local ATI_f = buffer:range(i+3,2)

        local mcc = mcc(plmn_f)
        local mnc = mnc(plmn_f)

        if mcc and mnc then
            subtree:add(pf.mcc_mnc, plmn_f, string.format('%s/%s (0x%06x)',mcc, mnc,  plmn_f:uint()))
            subtree:add(pf.ati, ATI_f)
        end
    end

    return buffer:len() -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
