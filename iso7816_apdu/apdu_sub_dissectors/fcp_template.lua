
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local p = Proto.new("iso7816.apdu.fcp", "FCP Template")
local pf = {
    info = ProtoField.string(p.name .. ".info", "Info"),
}
p.fields = pf

local df = 'apdu_sub_dissectors/fcp_template/'
local dt = DissectorTable.new('iso7816.apdu.fcp', 'ISO7816-APDU fcp template sub-dissectors', ftypes.UINT8, base.HEX, p)
dt:add(0x82, require(df .. 'file_descriptor'))
dt:add(0x83, require(df .. 'file_identifier'))
dt:add(0x88, require(df .. 'file_identifier_short'))
dt:add(0x84, require(df .. 'df_name_aid'))
dt:add(0xA5, require(df .. 'proprietary_info'))
dt:add(0x8A, require(df .. 'life_cycle_status'))
dt:add(0x8C, require(df .. 'security_attribute_compact'))
dt:add(0xAB, require(df .. 'security_attribute_expanded'))
dt:add(0x8B, require(df .. 'security_attribute_referenced_expanded'))
dt:add(0xC6, require(df .. 'pin_status'))
dt:add(0x80, require(df .. 'file_size'))
dt:add(0x81, require(df .. 'file_size_total'))

function p.dissector(buffer, pinfo, tree)

    -- FCP - File Control Parameters (in Response)
    -- see (TS 102 221) 11.1.1.3 Response Data
    -- see (TS 102 221) 11.1.1.3.0 Base coding
    local le = buffer(1, 1):uint()
    tree:add(pf.info, buffer:range(), string.format('FCP Template, Tag: 0x62, Content: %s byte(s)', le))
    local offset = 2

    ---- this will call the according sub-dissector for each section
    offset = offset + dissect_remaining_tlvs(buffer(offset), pinfo, tree, p, dt)

    return offset -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
