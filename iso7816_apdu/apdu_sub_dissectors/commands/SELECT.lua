
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

local p = Proto.new("iso7816.apdu.instructions.SELECT", "SELECT")
local pf = {
    p1 = ProtoField.uint8(p.name .. ".p1", "Parameter 1", base.HEX),
    p2 = ProtoField.uint8(p.name .. ".p2", "Parameter 2", base.HEX),
    le = ProtoField.uint8(p.name .. ".le", "Response Length (Parameter 3)", base.DEC),
    selected_file = ProtoField.string(p.name .. ".select.file", "File ID"),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)
    --local cla_f = buffer.range(0,1)
    --local ins_f = buffer:range(1,1)
    local p1_f =  buffer:range(2,1)
    local p2_f =  buffer:range(3,1)
    local le_f = buffer:range(4,1)
    local le = le_f:uint()
    local data_f = buffer:range(5,le)
    local offset = 0
    offset = offset + 5 + le

    tree:add(pf.p1, p1_f)
    tree:add(pf.p2, p2_f)
    tree:add(pf.le, le_f)

    local selected_file
    for i=0,le-2,2 do
        local selected_file_f = data_f:range(i,2)

        -- extract last selected file (file items make up a path, we just need the file id for parser selection)
        selected_file = selected_file_f:uint()

        -- print the whole path though
        tree:add(pf.selected_file, selected_file_f, string.format('%s (0x%04x)', FILE_IDENTIFIERS[selected_file], selected_file))
    end

    -- update selected file in conversation item
    if not pinfo.visited then
        get_current_conversation(pinfo).selected_file = selected_file
        print(string.format('frame: %s - SELECT - updating selected_file in current conversation', pinfo.number))
    end

    return offset -- processed bytes
end

return p -- returning protocol to add it into dissector table with require
