
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local FILE_TYPE = {
    [0] = "Working EF",
    [1] = "Internal EF",
    [2] = RFU,
    [3] = RFU,
    [4] = RFU,
    [5] = RFU,
    [6] = RFU,
    [7] = "DF or ADF",
}
local EF_STRUCTURE = {
    [0] = "No information given",
    [1] = "Transparent structure",
    [2] = "Linear fixed structure",
    [3] = RFU,
    [4] = RFU,
    [5] = RFU,
    [6] = "Cyclic structure",
    [7] = RFU,
    [9] = "BER-TLV structure" -- TODO this should actually be 57 0-111001
}

local p = Proto.new("iso7816.apdu.file_descriptor", "File Descriptor")
local pf = {
    section = ProtoField.string(p.name .. ".section", "Section"),
    byte = ProtoField.uint8(p.name .. ".byte", "Descriptor Byte", base.HEX),
    unused = ProtoField.uint8(p.name .. ".unused", "-", base.DEC, { [0] = 'unused' }, 0x80),
    file_sharable = ProtoField.uint8(p.name .. ".shareable", "File shareable", base.DEC, YES_NO, 0x40),
    file_type = ProtoField.uint8(p.name .. ".type", "File type", base.DEC, FILE_TYPE, 0x38),
    ef_structure = ProtoField.uint8(p.name .. ".ef_structure", "EF structure", base.DEC, EF_STRUCTURE, 0x07),
    data_coding = ProtoField.uint8(p.name .. ".data_coding", "Data Coding Byte", base.HEX),
    record_length = ProtoField.uint8(p.name .. ".record_length", "Record length"),
    number_of_records = ProtoField.uint8(p.name .. ".number_of_records", "Number of records"),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)

    -- optional, add a new level (dropdown) for this section
    local subtree = tree:add(p, buffer(0, buffer:len()))

    -- see (TS 102 221) 11.1.1.4.3 File descriptor
    subtree:add(pf.section, buffer(0, 2), string.format('Tag: 0x%2x, Content: %s byte(s)', buffer(0, 1):uint(), buffer(1, 1):uint()))
    subtree:add(pf.byte, buffer(2, 1))
    subtree:add(pf.unused, buffer(2, 1))
    subtree:add(pf.file_sharable, buffer(2, 1))
    subtree:add(pf.file_type, buffer(2, 1))
    subtree:add(pf.ef_structure, buffer(2, 1))
    subtree:add(pf.data_coding, buffer(3, 1))

    if buffer:len() == 7 then
        -- linear fixed and cyclic files
        subtree:add(pf.record_length, buffer(4, 2))
        subtree:add(pf.number_of_records, buffer(6, 1))

        local conversation = get_current_conversation(pinfo)
        if conversation and not pinfo.visited then
            print(string.format('frame: %s - file_descriptor - updating current conversation, expected read records', pinfo.number))

            conversation.expect_read_record_length = buffer(4, 2):uint() -- store this for conversation mapping
            conversation.expect_read_records_total = buffer(6, 1):uint() -- store this for conversation mapping
            --conversation.next_record_nr = 1 -- store this for conversation mapping
            --conversation.selected_record = 1 -- store this for conversation mapping
            --print(string.format('frame: %s - set expect_read_record_length to: %s', pinfo.number, _G.conversations[pinfo.number].expect_read_record_length))
            --print(string.format('frame: %s - set expect_read_records_total to: %s', pinfo.number, _G.conversations[pinfo.number].expect_read_records_total))
            --print(string.format('frame: %s - set next_read_record_nr to: %s', pinfo.number, _G.conversations[pinfo.number].next_read_record_nr))

        end
        return 7 -- processed bytes
    end

    return 4 -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
