-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

local p = Proto.new("iso7816.apdu.instructions.GET_RESPONSE", "GET_RESPONSE")
local pf = {
    p1 = ProtoField.uint8(p.name .. ".p1", "Parameter 1", base.HEX),
    p2 = ProtoField.uint8(p.name .. ".p2", "Parameter 2", base.HEX),
    le = ProtoField.uint8(p.name .. ".le", "APDU Payload Length (Parameter 3)", base.DEC),
    data = ProtoField.bytes(p.name .. ".data", "APDU Payload"),
}
p.fields = pf

local dt = DissectorTable.new('iso7816.apdu', 'ISO7816-APDU sub-dissectors', ftypes.UINT8, base.HEX, p)
dt:add(0x62, require('apdu_sub_dissectors/fcp_template'))

function p.dissector(buffer, pinfo, tree)
    --local cla_f = buffer.range(0,1)
    --local ins_f = buffer:range(1,1)
    local p1_f = buffer:range(2, 1)
    local p2_f = buffer:range(3, 1)
    local le_f = buffer:range(4, 1)
    local le = le_f:uint()
    local data_f = buffer:range(5, le)
    --local sw_f = buffer:range(5 + le, 2)
    --local sw1 = sw_f:range(0, 1):uint() -- status 61: response ready, 90: normal end
    --local sw2 = sw_f:range(1, 1):uint() -- expected response length
    local offset = 0
    offset = offset + 5 + le

    tree:add(pf.p1, p1_f)
    tree:add(pf.p2, p2_f)
    tree:add(pf.le, le_f)
    tree:add(pf.data, data_f)

    local previous = find_previous_conversation(pinfo, INSTRUCTIONS_CODE.SELECT)
    if previous then
        print(string.format('frame: %s - CONVERSATIONS - GET_RESPONSE found previous SELECT in frame: %s', pinfo.number, previous.frame_number))
    end
    if not pinfo.visited
            and previous
            and previous.status == STATUS_CODE.RESPONSE_READY
            and previous.expect_response_length == le then
        local current = previous:create_successor(buffer, pinfo)
        print(string.format('frame: %s - CONVERSATIONS - GET_RESPONSE in frame: %s , following %s in startframe: %s', pinfo.number, current.frame_number, INSTRUCTIONS[current.conversation_start.instruction], current.conversation_start_frame))
        set_current_conversation(pinfo, current)
    end

    return dissect_response_tlvs(data_f:range():tvb(), pinfo, tree, p, dt)
    end

return p -- returning protocol to add it into dissector table with require
