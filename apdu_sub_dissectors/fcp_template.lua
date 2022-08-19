local p = Proto.new("iso7816.apdu.fcp", "FCP Template")
local pf = {
    info = ProtoField.string(p.name .. ".info", "Info"),
}
p.fields = pf

local dt = DissectorTable.new('iso7816.apdu.fcp', 'ISO7816-APDU fcp template sub-dissectors', ftypes.UINT8, base.HEX, p)
dt:add(0x82, require('apdu_sub_dissectors/fcp_template/file_descriptor'))
dt:add(0x83, require('apdu_sub_dissectors/fcp_template/file_identifier'))
dt:add(0x84, require('apdu_sub_dissectors/fcp_template/df_name_aid'))
dt:add(0xA5, require('apdu_sub_dissectors/fcp_template/proprietary_info'))

function p.dissector(buffer, pinfo, tree)

    -- FCP - File Control Parameters (in Response)
    -- see (TS 102 221) 11.1.1.3 Response Data
    -- see (TS 102 221) 11.1.1.3.0 Base coding
    tree:add(pf.info, buffer(0, 2), string.format('FCP Template, Tag: 0x62, Length: %s bytes', buffer(1, 1):uint()))
    local offset = 2

    ---- this will call the according sub-dissector for each section
    offset = offset + dissect_remaining_tlvs(buffer(offset), pinfo, tree, p, dt)

    return offset -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
