
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

-- Meta class
APDU_Conversation = {
    conversation_start = nil,
    previous = nil,
    frame_number = 0,
    conversation_start_frame = 0,
    instruction = 0x00,
    offset = 0,
    length = 0,
    status = 0x00,
    selected_file = nil,
    selected_record_nr = nil,

    -- expect follow up GET RESPONSE
    expect_response_length = 0x00, -- from SELECT's SW first byte, to match following GET RESPONSE gsm_sim.le

    -- expect follow up read binary
    expect_read_binary_offset = 0, -- from GET RESPONSE proprietary info 3rd++ byte, to match following READ BINARY offset
    expect_read_binary_file_size = 0, -- from GET RESPONSE file size info 3rd++ byte, to match following READ BINARY expected response length

    -- expect follow up read record
    expect_read_record_length = 0, -- from GET RESPONSE file descriptor 7th byte, to match following READ RECORD length
    expect_read_records_total = 0, -- from GET RESPONSE file descriptor 5+6th byte, to match following READ RECORD length
    next_record_nr = 0, -- set to currently read record, so next record can see if it's in sequence

}
APDU_Conversation.__index = APDU_Conversation


--Derived class method new
function APDU_Conversation:new (buffer, pinfo)
    --local cla_f = buffer.range(0,1)
    local ins_f = buffer:range(1,1)
    local ins = ins_f:uint()
    local p1_f =  buffer:range(2,1)
    local p2_f =  buffer:range(3,1)

    local sfi_and_offset_f = buffer:range(2, 2)
    local sfi_marker = sfi_and_offset_f:bitfield(0, 1)
    local read_binary_offset = sfi_and_offset_f:bitfield(1, 15)
    local has_sfi = sfi_marker == 0x1

    local le_f = buffer:range(4,1)
    local le = le_f:uint()
    --local data_f = buffer:range(5,le)
    local sw_f = buffer:range(5 + le, 2)
    local sw1 = sw_f:range(0, 1):uint() -- status 61: response ready, 90: normal end
    local sw2 = sw_f:range(1, 1):uint() -- expected response length

    -- : notation -> self as hidden first param (self == APDU_Conversation)
    local o = {}
    setmetatable(o, self) -- set defaults and methods of APDU_Conversation to new object
    o.frame_number = pinfo.number
    o.instruction = ins or 0x00
    o.offset = not has_sfi and read_binary_offset or 0
    o.length = le or 0
    o.status = sw1 or 0x00
    o.expect_response_length = sw2 or  nil
    o.conversation_start_frame =  pinfo.number
    o.conversation_start = o
    return o
end

function APDU_Conversation:create_successor(buffer, pinfo)
    local successor = APDU_Conversation:new(buffer, pinfo)
    successor.conversation_start_frame = self.conversation_start_frame
    successor.conversation_start = self.conversation_start
    successor.selected_file = self.selected_file
    successor.selected_record_nr = self.selected_record_nr
    successor.expect_read_binary_file_size = self.expect_read_binary_file_size
    successor.expect_read_records_total = self.expect_read_records_total
    successor.expect_read_record_length = self.expect_read_record_length
    successor.previous = self
    return successor
end
