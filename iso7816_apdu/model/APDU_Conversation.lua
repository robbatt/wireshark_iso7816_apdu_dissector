
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

-- Meta class
APDU_Conversation = {
    conversation_start = nil,
    previous = nil,
    frame_number = 0,
    conversation_start_frame = 0,
    instruction = 0x00,
    length = 0x00,
    status = 0x00,
    selected_file = nil,

    -- expect follow up GET RESPONSE
    expect_response_length = 0x00, -- from SELECT's SW first byte, to match following GET RESPONSE gsm_sim.le

    -- expect follow up read binary
    expect_read_binary_offset = 0x00, -- from GET RESPONSE proprietary info 3rd++ byte, to match following READ BINARY offset
    expect_read_binary_file_size = 0x00, -- from GET RESPONSE file size info 3rd++ byte, to match following READ BINARY expected response length

    -- expect follow up read record
    expect_read_record_length = 0x00, -- from GET RESPONSE file descriptor 7th byte, to match following READ RECORD length
    expect_read_records_total = 0, -- from GET RESPONSE file descriptor 5+6th byte, to match following READ RECORD length
    next_read_record_nr = 0, -- set to currently read record, so next record can see if it's in sequence

}
APDU_Conversation.__index = APDU_Conversation


--Derived class method new
function APDU_Conversation:new (pinfo, instruction, length, status, expect_response_length)
    -- : notation -> self as hidden first param (self == APDU_Conversation)
    local o = {}
    setmetatable(o, self) -- set defaults and methods of APDU_Conversation to new object
    o.frame_number = pinfo.number
    o.instruction = instruction or 0x00
    o.length = length or 0
    o.status = status or 0x00
    o.expect_response_length = expect_response_length or  nil
    o.conversation_start_frame =  pinfo.number
    o.conversation_start = o
    return o
end

function APDU_Conversation:create_successor(pinfo, instruction, length, status, expect_response_length)
    local successor = APDU_Conversation:new(pinfo,instruction,length, status,expect_response_length)
    successor.conversation_start_frame = self.conversation_start_frame
    successor.conversation_start = self.conversation_start
    successor.selected_file = self.selected_file
    successor.previous = self
    return successor
end
