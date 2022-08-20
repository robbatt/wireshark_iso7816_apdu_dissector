
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

-- Meta class
APDU_Conversation = {
    frame_number = 0,
    conversation_start_frame = 0,
    instruction = 0x00,
    selected_file = 0x0000,

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

-- Derived class method new

function APDU_Conversation:new (frame_number, instruction)
    --o = o or {}
    setmetatable(APDU_Conversation, self)
    self.__index = self
    self.frame_number = frame_number or 0
    self.instruction = instruction or 0x00
    return self
end

-- Derived class method

--function APDU_Conversation:method_name()
--    print("Test: ", self.instruction)
--end