-- enable loading of our modules
_G['iso7816_apdu'] = {
    ["__DIR__"] = __DIR__,
    ["__DIR_SEPARATOR__"] = __DIR_SEPARATOR__,
}

-- help wireshark find our modules
package.prepend_path("iso7816_apdu")

require('constants')
require('util')
require('model/APDU_Conversation')
require('conversations')
require('bit_operations')
require('parsers')


-- Step 1 - document as you go. See header above and set_plugin_info().
local iso7816_adpu_info = {
    version = "1.0.0",
    author = "Robert Brendler",
    description = "A dissector to handle missing ADPU info in existing ISO7816 dissector",
    repository = "https://github.com/robbatt/wireshark_iso7816_adpu_dissector.git"
}
set_plugin_info(iso7816_adpu_info)

-- Step 2 - create a protocol to attach new fields to
local p = Proto.new("iso7816.apdu", "ISO 7816 - APDU")

local conversation_dissector = require('apdu_sub_dissectors/conversations').dissector
local command_dissector = require('apdu_sub_dissectors/commands').dissector
local status_dissector = require('apdu_sub_dissectors/status').dissector

-- Step 3 - add some field(s) to Step 2 protocol
local pf = {
    conversation = ProtoField.string(p.name .. ".conversation", "Conversation"),
}
p.fields = pf

-- Step 4 - create a Field extractor to copy packet field data.
iso7816_gsm_sim_f = Field.new('gsm_sim')
iso7816_apdu_sw_f = Field.new('gsm_sim.apdu.sw')

-- Step 5 - create the postdissector function that will run on each frame/packet
function p.dissector(tvb, pinfo, tree)
    -- copy already processed field(s)
    local offset = 0
    local gsm_sim = iso7816_gsm_sim_f()
    local sw_f = iso7816_apdu_sw_f()

    local subtree_apdu = tree:add(p, gsm_sim, 'Iso7816 APDU')
    local subtree_conversations = subtree_apdu:add(pf.conversation, gsm_sim.range(), 'none detected')

    -- dissect APDU command
    offset = offset + command_dissector:call(gsm_sim.range():tvb(), pinfo, subtree_apdu)

    -- dissect APDU status word
    offset = offset + status_dissector:call(sw_f.range():tvb(), pinfo, subtree_apdu)

    -- dissect APDU command conversation (don't count dissected bytes, command dissector will)
    conversation_dissector:call(gsm_sim.range():tvb(), pinfo, subtree_conversations)

    local current = get_current_conversation(pinfo)
    if current then
        if current.frame_number == current.conversation_start_frame then
            subtree_conversations:set_text(string.format('Conversation: start %s', INSTRUCTIONS[current.instruction]))
        else
            subtree_conversations:set_text(string.format('Conversation: start at %s (frame %s) - current: %s', INSTRUCTIONS[current.conversation_start.instruction], current.conversation_start_frame, INSTRUCTIONS[current.instruction]))
        end
        if current.selected_file then
            subtree_conversations:append_text(string.format(' - file: %s', FILE_IDENTIFIERS[current.selected_file] or 0x00))
        end
    end

    --print(string.format('frame: %s - buffer len: %s , bytes dissected: %s', pinfo.number, gsm_sim.tvb:len(), offset))

    return offset
end

-- Step 6 - register the new protocol as a postdissector
register_postdissector(p)

-- disable loading of our modules
_G['iso7816_apdu'] = nil