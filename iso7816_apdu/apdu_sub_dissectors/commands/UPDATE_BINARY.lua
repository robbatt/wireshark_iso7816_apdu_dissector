
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local p = Proto.new("iso7816.apdu.instructions.UPDATE_BINARY", "UPDATE_BINARY")
local pf = {
    sfi_and_offset = ProtoField.uint16(p.name .. ".update_binary", "Offset and SFI", base.HEX),
    sfi_marker = ProtoField.uint16(p.name .. ".update_binary.sfi_marker", "SFI used", base.DEC, YES_NO, 0x8000),
    sfi = ProtoField.uint16(p.name .. ".update_binary.sfi", "SFI", base.HEX, SFI_FILE_IDENTIFIERS, 0x1f00),
    sfi_read_binary_offset = ProtoField.uint16(p.name .. ".update_binary.sfi_offset", "SFI Read offset", base.DEC, nil, 0x00ff),

    read_binary_offset = ProtoField.uint16(p.name .. ".update_binary.offset", "Read offset", base.DEC, nil, 0x7fff),
    read_binary_length = ProtoField.uint8(p.name .. ".update_binary.length", "Read length", base.DEC),
    selected_file = ProtoField.string(p.name .. ".update_binary.file", "Selected file"),

    data = ProtoField.bytes(p.name .. ".update_binary.data", "Data"),
    no_parser = ProtoField.string(p.name .. ".update_binary.no_parser", "No parser"),
}
p.fields = pf
function p.dissector(buffer, pinfo, tree)
    --local buffer = gsm_sim.tvb(1,4)
    --e.g. (0x b0 82 00 09 ) b0: READ BINARY, 82: 8:->SFI marker 0x1, 2:-> 0x02 SFI, 00: offset, 09: length
    local offset = 0
    --local instruction = buffer:range(0, 1)
    local sfi_and_offset_f = buffer:range(2, 2)
    local read_binary_offset = sfi_and_offset_f:bitfield(1, 15)
    local le_f = buffer:range(4, 1)
    local le = le_f:uint()
    local data_f = buffer:range(5, le)
    offset = offset + 5

    local selected_file = nil

    tree:add(pf.sfi_and_offset, sfi_and_offset_f)
    tree:add(pf.sfi_marker, sfi_and_offset_f)

    local sfi_marker = sfi_and_offset_f:bitfield(0, 1)
    if sfi_marker == 0x1 then
        -- SFI present, so file can be read directly
        local sfi = buffer:range(2, 1):bitfield(3, 5)
        selected_file = SFI_FILE_MAPPING[sfi]
        tree:add(pf.sfi, sfi_and_offset_f)
        tree:add(pf.sfi_read_binary_offset, sfi_and_offset_f)

    elseif read_binary_offset >= 0 then
        -- this is a follow up to a GET_RESPONSE or READ_BINARY
        local previous_ins = read_binary_offset == 0 and INSTRUCTIONS_CODE.GET_RESPONSE or INSTRUCTIONS_CODE.READ_BINARY
        local previous = find_previous_conversation(pinfo, previous_ins)
        if previous and previous.expect_read_binary_offset == read_binary_offset then
            local current = previous:create_successor(buffer, pinfo)
            if read_binary_offset + le < previous.expect_read_binary_file_size then
                current.expect_read_binary_offset = read_binary_offset + le
                --print(string.format('frame: %s - CONVERSATIONS - READ_BINARY expect FOLLOW UP with offset: %s', pinfo.number, current.expect_read_binary_offset))
            end
            selected_file = current.selected_file
            set_current_conversation(pinfo, current)
            --print(string.format('frame: %s - CONVERSATIONS - READ_BINARY in frame: %s , following %s in startframe: %s, selected file: %s', pinfo.number, current.frame_number, INSTRUCTIONS[current.conversation_start.instruction], current.conversation_start_frame, current.selected_file))
        end
        tree:add(pf.read_binary_offset, read_binary_offset)
    end

    local current = get_current_conversation(pinfo)
    selected_file = selected_file or current and current.selected_file

    tree:add(pf.read_binary_length, le_f)
    tree:add(pf.selected_file, data_f, string.format('0x%04x - %s', selected_file, FILE_IDENTIFIERS[selected_file]))
    tree:add(pf.data, data_f)

    local processed_bytes = dissect_file_content(data_f, pinfo, tree, p, dt_file_parsers, selected_file)
    offset = offset + processed_bytes

    if processed_bytes == 0 then
        tree:add(pf.no_parser, buffer:range(5, le), string.format('No file content parser found for file: 0x%02x - %s', selected_file, FILE_IDENTIFIERS[selected_file]))
    end

    return offset -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
