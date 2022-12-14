
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local p = Proto.new("iso7816.apdu.proprietary_info", "Proprietary Information")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    data = ProtoField.bytes(p.name .. ".data", "Data"),
}
p.fields = pf

local df = 'apdu_sub_dissectors/fcp_template/proprietary_info/'
local dt = DissectorTable.new('iso7816.apdu.fcp.proprietary_info', 'ISO7816-APDU fcp template - proprietary info - sub-dissectors', ftypes.UINT8, base.HEX, p)
dt:add(0x80, require(df .. 'uicc_characteristics'))
dt:add(0x81, require(df .. 'application_power_consumption'))
dt:add(0x82, require(df .. 'minimum_application_clock_frequency'))
dt:add(0x83, require(df .. 'amount_of_available_memory'))
dt:add(0x84, require(df .. 'file_details'))
dt:add(0x85, require(df .. 'reserved_file_size'))
dt:add(0x86, require(df .. 'maximum_file_size'))
dt:add(0x87, require(df .. 'supported_system_commands'))
dt:add(0x88, require(df .. 'specific_uicc_environmental_conditions'))
dt:add(0x89, require(df .. 'platform_to_platform_CAT_Secured_APDU'))
dt:add(0xc0, require(df .. 'expect_read_binary'))

function p.dissector(buffer, pinfo, tree)

    local length = buffer:len()
    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, length))

    -- Mandatory for MF, optional for DF/ADF
    -- see (TS 102 221) 11.1.1.4.6 Proprietary information
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))
    subtree:add(pf.data, buffer(2, length - 2))

    local offset = 2

    -- this will call the according sub-dissector for each section
    offset = offset + dissect_response_tlvs(buffer(offset):tvb(), pinfo, tree, p, dt)

    return offset -- processed bytes
end

return p -- returning protocol to add it into dissector table with require