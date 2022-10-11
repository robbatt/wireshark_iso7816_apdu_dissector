-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

READ_RECORD_MODE_CODES = {
    NEXT_RECORD = 0x2,
    PREVIOUS_RECORD = 0x3,
    ABSOLUTE = 0x4,
}
READ_RECORD_MODES = {
    [0x2] = 'NEXT RECORD',
    [0x3] = 'PREVIOUS RECORD',
    [0x4] = 'ABSOLUTE',
}

local p = Proto.new("iso7816.apdu.instructions.READ_RECORD", "READ_RECORD")
local pf = {
    record_nr = ProtoField.uint8(p.name .. ".read_record.nr", "Record Number", base.DEC),
    record_sfi = ProtoField.uint8(p.name .. ".read_record.sfi", "Record Address (SFI)", base.HEX, SFI_FILE_IDENTIFIERS, 0xf8),
    record_mode = ProtoField.uint8(p.name .. ".read_record.mode", "Read Mode", base.HEX, READ_RECORD_MODES, 0x07),
    read_record_length = ProtoField.uint8(p.name .. ".read_record.length", "Read length", base.DEC),

    selected_file = ProtoField.string(p.name .. ".read_record.file", "Selected file"),
    data = ProtoField.bytes(p.name .. ".read_record.data", "Data"),
    no_parser = ProtoField.string(p.name .. ".read_record.no_parser", "No parser"),
}
p.fields = pf

iso7816_gsm_sim_record_nr_f = Field.new('gsm_sim.record_nr')

function p.dissector(buffer, pinfo, tree)
    --local buffer = gsm_sim.tvb(1,4)
    --e.g. (0x b0 82 00 09 ) b0: READ BINARY, 82: 8:->SFI marker 0x1, 2:-> 0x02 SFI, 00: offset, 09: length
    local offset = 0
    local instruction = buffer:range(0, 1)
    local p1_f = buffer:range(2, 1)
    local p2_f = buffer:range(3, 1)
    local le_f = buffer:range(4, 1)
    local le = le_f:uint()
    local data_f = buffer:range(5, le)
    offset = offset + 5
    local record_nr = p1_f:uint() --  f_val(iso7816_gsm_sim_record_nr_f)
    local record_sfi = p2_f:bitfield(0, 5)
    local record_mode = p2_f:bitfield(5, 3)

    local is_absolute = record_mode == READ_RECORD_MODE_CODES.ABSOLUTE
    local is_absolute_current = is_absolute and record_sfi == 0x00

    local selected_file
    if is_absolute_current  then
    --if is_absolute_current and not pinfo.visited then
        -- get file from conversation
        -- this is a follow up to a GET_RESPONSE
        local previous = find_previous_conversation(pinfo, INSTRUCTIONS_CODE.GET_RESPONSE)
        print(string.format('frame: %s - CONVERSATIONS - READ_RECORD ## record nr: %s, le: %s, expect le: %s', pinfo.number, record_nr, le, previous.expect_read_record_length))

        if previous
                --and record_nr == previous.next_record_nr
                and le == previous.expect_read_record_length
                --and record_nr < previous.expect_read_records_total
        then
            local current = previous:create_successor(buffer, pinfo)
            current.selected_record_nr = record_nr
            selected_file = current.selected_file
            set_current_conversation(pinfo, current)
            print(string.format('frame: %s - CONVERSATIONS - READ_RECORD in frame: %s , following %s in startframe: %s, selected file: %s', pinfo.number, current.frame_number, INSTRUCTIONS[current.conversation_start.instruction], current.conversation_start_frame, FILE_IDENTIFIERS[current.selected_file]))
        end
    elseif is_absolute then
        selected_file = SFI_FILE_MAPPING[record_sfi]
    end

    local selected_file_string
    if is_absolute_current then
        selected_file_string = string.format('Currently selected EF - %s (0x%04x)', FILE_IDENTIFIERS[selected_file], selected_file or 0)
    elseif is_absolute then
        selected_file_string = string.format('0x%04x - %s', record_sfi or 0x00, SFI_FILE_IDENTIFIERS[record_sfi])
    elseif record_mode == READ_RECORD_MODE_CODES.NEXT_RECORD then
        selected_file_string = string.format('Next record (not implemented)')
    elseif record_mode == READ_RECORD_MODE_CODES.PREVIOUS_RECORD then
        selected_file_string = string.format('Previous record (not implemented)')
    end

    tree:add(pf.record_nr, p1_f)
    tree:add(pf.record_sfi, p2_f)
    tree:add(pf.record_mode, p2_f)
    tree:add(pf.read_record_length, le_f)
    tree:add(pf.selected_file, data_f, selected_file_string)
    tree:add(pf.data, data_f)

    local processed_bytes = dissect_file_content(data_f, pinfo, tree, p, dt_record_parsers, selected_file)
    offset = offset + processed_bytes

    if processed_bytes == 0 then
        tree:add(pf.no_parser, data_f, string.format('No record content parser found for file: 0x%02x - %s', selected_file, FILE_IDENTIFIERS[selected_file]))
    end

    return offset -- processed bytes

end

return p -- returning protocol to add it into dissector table with require
