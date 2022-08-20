-- enable loading of our modules
_G['iso7816_apdu'] = {
    ["__DIR__"] = __DIR__,
    ["__DIR_SEPARATOR__"] = __DIR_SEPARATOR__,
}

-- help wireshark find our modules
package.prepend_path("iso7816_apdu")

require('constants')
require('util')
require('conversations')

_G.conversations = {}

-- Step 1 - document as you go. See header above and set_plugin_info().
local iso7816_adpu_info = {
    version = "1.0.0",
    author = "Robert Brendler",
    description = "A dissector to handle missing ADPU info in existing ISO7816 dissector",
    repository = "https://github.com/robbatt/wireshark_iso7816_adpu_dissector.git"
}
set_plugin_info(iso7816_adpu_info)

-- Step 2 - create a protocol to attach new fields to
local p = Proto.new("iso7816.apdu", "ISO 7816 - APDU")

local dt = DissectorTable.new('iso7816.apdu', 'ISO7816-APDU sub-dissectors', ftypes.UINT8, base.HEX, p)
dt:add(0x62, require('apdu_sub_dissectors/fcp_template'))

local dt_parsers = DissectorTable.new('iso7816.apdu.file_parsers', 'ISO7816-APDU file parsers', ftypes.UINT8, base.HEX, p)
dt_parsers:add(0x2fe2, require('apdu_sub_dissectors/file_parsers/iccid'))

-- Step 3 - add some field(s) to Step 2 protocol
local pf = {
    data = ProtoField.bytes(p.name .. ".data", "Data"),
    followup_frame = ProtoField.string(p.name .. ".followup.frame", "Follow up to frame "),
    followup_select = ProtoField.uint16(p.name .. ".followup.select_file", "Follow up to select", base.HEX, FILE_IDENTIFIERS),
}
p.fields = pf

-- Step 4 - create a Field extractor to copy packet field data.
iso7816_apdu_data_f = Field.new('gsm_sim.apdu.data')
iso7816_apdu_ins_f = Field.new('gsm_sim.apdu.ins')
iso7816_gsm_sim_le_f = Field.new('gsm_sim.le')
iso7816_gsm_sim_bin_offset_f = Field.new('gsm_sim.bin_offset')
iso7816_gsm_sim_record_nr_f = Field.new('gsm_sim.record_nr')
iso7816_apdu_sw_f = Field.new('gsm_sim.apdu.sw')
iso7816_gsm_sim_file_id_f = Field.new('gsm_sim.file_id')

f_val = function(field_func, default)
    default = default or nil
    local field = field_func()
    if (field) then
        return field.value
    else
        return default
    end
end

-- Step 5 - create the postdissector function that will run on each frame/packet
function p.dissector(tvb, pinfo, tree)
    -- copy already processed field(s)
    local apdu_payload = iso7816_apdu_data_f()
    local ins = f_val(iso7816_apdu_ins_f)
    local le = f_val(iso7816_gsm_sim_le_f)
    local bin_off = f_val(iso7816_gsm_sim_bin_offset_f)
    local record_nr = f_val(iso7816_gsm_sim_record_nr_f)
    local sw_f = iso7816_apdu_sw_f()

    local offset = 0
    local previous = _G.conversations[pinfo.number - 1]

    if ins == 0xa4 and sw_f and sw_f.tvb(0, 1):uint() == 0x61 then
        -- select with response ready
        local sw2 = sw_f.tvb(1, 1):uint() -- expected response length
        local selected_file = f_val(iso7816_gsm_sim_file_id_f)
        --print(string.format('frame: %s - found select (file id: 0x%04x - %s)', pinfo.number, selected_file, FILE_IDENTIFIERS[selected_file]))

        local conversation = APDU_Conversation:new(pinfo.number, ins)
        -- TODO seems SELECT can also reference 2 files at once, but this field only stores one value (simtrace2_bg95_boot_roam_profile.pcapng - frame:29)
        conversation.selected_file = selected_file
        conversation.expect_response_length = sw2
        conversation.conversation_start_frame = pinfo.number
        _G.conversations[pinfo.number] = conversation

    elseif ins == 0xc0
            and le
            and previous
            and previous.expect_response_length == le
    then
        -- response
        --print(string.format('frame: %s - found matching response to previous select (file id: 0x%04x - %s)', pinfo.number, previous.selected_file, FILE_IDENTIFIERS[previous.selected_file]))

        local current = deepcopy(previous)
        current.instruction = ins
        current.frame_number = pinfo.number
        current.expect_response_length = 0x00
        _G.conversations[pinfo.number] = current

    elseif ins == 0xb2
            and previous
            and le and le == previous.expect_read_record_length
            and record_nr and record_nr == previous.next_read_record_nr
    then
        -- read record after response
        -- TODO currently works only for one READ RECORD after a GET RESPONSE, and for multiple without interruption through TERMINAL RESPONSE or FETCH proactive
        --print(string.format('frame: %s - found matching read record to previous select (file id: 0x%04x - %s) response', pinfo.number, previous.selected_file, FILE_IDENTIFIERS[previous.selected_file]))

        local current = deepcopy(previous)
        current.instruction = ins
        current.frame_number = pinfo.number
        current.expect_read_record_length = 0x00
        current.next_read_record_nr = 0x00
        _G.conversations[pinfo.number] = current

    elseif ins == 0xb0
            and previous
            and le and le == previous.expect_read_binary_file_size
            and bin_off and bin_off == previous.expect_read_binary_offset
    then
        -- read binary after response
        -- TODO currently works only for one READ BINARY after a GET RESPONSE
        --print(string.format('frame: %s - found matching read binary to previous select (file id: 0x%04x - %s) response', pinfo.number, previous.selected_file, FILE_IDENTIFIERS[previous.selected_file]))

        local current = deepcopy(previous)
        current.instruction = ins
        current.frame_number = pinfo.number
        current.expect_read_binary_offset = 0x00
        current.expect_read_binary_file_size = 0x00
        _G.conversations[pinfo.number] = current
    end

    if apdu_payload then
        -- override protocol column
        pinfo.cols.protocol:append(' - APDU')

        -- this will call the according sub-dissector for each section
        local buffer = apdu_payload.tvb
        local subtree = tree:add(p, buffer, 'Iso7816 APDU Data')
        subtree:add(pf.data, buffer)

        local current = _G.conversations[pinfo.number]

        if current and current.conversation_start_frame > 0 then
            subtree:add(pf.followup_frame, buffer, current.conversation_start_frame)
        end

        if ins == 0xb0 and current and current.selected_file > 0x00 then
            subtree:add(pf.followup_select, buffer, current.selected_file)
            -- parse binary content
            offset = offset + dissect_file_content(buffer, pinfo, subtree, p, dt_parsers, current.selected_file)
        else
            offset = offset + dissect_remaining_tlvs(buffer, pinfo, subtree, p, dt)
        end

    end

    return offset
end

-- Step 6 - register the new protocol as a postdissector
register_postdissector(p)

-- disable loading of our modules
_G['iso7816_apdu'] = nil