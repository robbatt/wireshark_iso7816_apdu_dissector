-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

local p = Proto.new("iso7816.apdu.conversations", "ISO7816-APDU conversations")
local pf = {
    conversation_start_frame = ProtoField.uint8(p.name .. ".conversation.start_frame", "Conversation start frame", base.DEC),
    conversation_select_file = ProtoField.uint16(p.name .. ".conversation.select_file", "Conversation File ID", base.HEX, FILE_IDENTIFIERS),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    --local cla = buffer.range(0,1):uint()
    local ins = buffer:range(1, 1):uint()
    --local p1 = buffer.range(2,1):uint()
    --local p2 = buffer.range(3,1):uint()
    local le = buffer:range(4, 1):uint()
    local sw_f = buffer:range(5 + le, 2)
    local sw1 = sw_f:range(0, 1):uint() -- status 61: response ready, 90: normal end
    local sw2 = sw_f:range(1, 1):uint() -- expected response length

    local sfi_and_offset_f = buffer:range(2, 2)
    local has_sfi = sfi_and_offset_f:bitfield(0, 1) == 0x1
    local sfi = buffer:range(2, 1):bitfield(3, 5)
    local selected_sfi_file = SFI_FILE_MAPPING[sfi]

    local previous = get_previous_conversation(pinfo)
    local current


    -- conditions
    local is_select_with_response = ins == INSTRUCTIONS_CODE.SELECT
            and sw1 == STATUS_CODE.RESPONSE_READY
            and sw2 > 0

    local is_get_response_matching_previous_select = ins == INSTRUCTIONS_CODE.GET_RESPONSE
            and previous
            and previous.instruction == INSTRUCTIONS_CODE.SELECT
            and previous.status == STATUS_CODE.RESPONSE_READY
            and previous.expect_response_length > 0

    local is_read_binary_matching_previous_get_response = ins == INSTRUCTIONS_CODE.READ_BINARY
            and previous
            and previous.instruction == INSTRUCTIONS_CODE.GET_RESPONSE
            and le <= previous.expect_read_binary_file_size
            and previous.expect_read_binary_offset and previous.expect_read_binary_offset >= 0
            and not has_sfi or (has_sfi and selected_sfi_file == previous.selected_file)

    -- get or create current conversation item
    if pinfo.visited then
        current = get_current_conversation(pinfo) -- get already stored conversation item
        --print(string.format('frame: %s - CONVERSATIONS - STORED %s in frame: %s , following %s in startframe: %s', pinfo.number, INSTRUCTIONS[current.instruction], current.frame_number, INSTRUCTIONS[current.conversation_start.instruction], current.conversation_start_frame))
    else
        if is_get_response_matching_previous_select then
            current = previous:create_successor(pinfo, ins, le, sw1, sw2) -- deepcopy(previous) -- copy conversation data from previous frame
            print(string.format('frame: %s - CONVERSATIONS - GET_RESPONSE in frame: %s , following %s in startframe: %s', pinfo.number, current.frame_number, INSTRUCTIONS[current.conversation_start.instruction], current.conversation_start_frame))

        elseif is_read_binary_matching_previous_get_response then
            current = previous:create_successor(pinfo, ins, le, sw1, sw2) -- deepcopy(previous)
            print(string.format('frame: %s - CONVERSATIONS - READ_BINARY in frame: %s , following %s in startframe: %s', pinfo.number, current.frame_number, INSTRUCTIONS[current.conversation_start.instruction], current.conversation_start_frame))

        else
            current = APDU_Conversation:new(pinfo, ins, le, sw1, sw2)
            print(string.format('frame: %s - CONVERSATIONS - NEW conversation %s in frame: %s ', pinfo.number, INSTRUCTIONS[current.instruction], current.frame_number))

        end
        set_current_conversation(pinfo, current)
    end

    -- display
    if is_select_with_response
            or is_get_response_matching_previous_select
            or is_read_binary_matching_previous_get_response then
        tree:add(pf.conversation_start_frame, buffer:range(), current.conversation_start_frame)
        tree:add(pf.conversation_select_file, buffer:range(), current.selected_file)
    end

    return 0
end

function set_current_conversation(pinfo, conversation)
    if get_current_conversation(pinfo) == nil then
        _G.conversations[pinfo.number] = conversation
    end
end
function get_current_conversation(pinfo)
    return _G.conversations[pinfo.number]
end
function get_previous_conversation(pinfo)
    return _G.conversations[pinfo.number - 1]
end

return p -- returning protocol to add it into dissector table with require
