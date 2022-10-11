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
    local current = get_current_conversation(pinfo)
    if current then
        tree:add(pf.conversation_start_frame, buffer:range(), current.conversation_start_frame)
        tree:add(pf.conversation_select_file, buffer:range(), current.selected_file)
    end
    return 0
end

return p -- returning protocol to add it into dissector table with require
