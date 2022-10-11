-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

_G.conversations = {}

function set_current_conversation(pinfo, conversation)
    local current = get_current_conversation(pinfo)
    if not current and conversation then
        _G.conversations[pinfo.number] = conversation
        print(string.format('frame: %s - CONVERSATIONS - set current conversation %s in frame: %s ', pinfo.number, INSTRUCTIONS[conversation.instruction], conversation.frame_number))
    end
end

function get_current_conversation(pinfo)
    return table.safe_get(_G.conversations, pinfo.number, nil)
end

function find_previous_conversation(pinfo, instruction)
    local current_frame = pinfo.number
    for previous_frame = current_frame, 1, -1 do
        local previous = table.safe_get(_G.conversations, previous_frame, nil)
        if previous and previous.instruction == instruction then
            return previous
        end
    end
end

