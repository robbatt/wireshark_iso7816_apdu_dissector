-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then
    return
end

CLA_CODING = {
    [0x0] = 'ISO/IEC 7816-4'
}

SECURE_MESSAGING_INDICATOR = {
    [0x00] = 'No SM used between terminal and card'
}

--ETSI TS 102 221 V17.1.0 (2022-02) p.78/79
INSTRUCTIONS_CODE = {
    SELECT = 0xa4,
    GET_RESPONSE = 0xc0,
    READ_BINARY = 0xb0,
    READ_RECORD = 0xb2,
    UPDATE_BINARY = 0xd6,
    UPDATE_RECORD = 0xdc,
}

INSTRUCTIONS = {
    -- Command APDUs
    [0xa4] = 'SELECT', -- CLA value '0X' or '4X' or '6X'
    [0xf2] = 'STATUS', -- CLA value '8X' or 'CX' or 'EX'
    [0xb0] = 'READ BINARY', -- CLA value '0X' or '4X' or '6X'
    [0xd6] = 'UPDATE BINARY', -- CLA value '0X' or '4X' or '6X'
    [0xb2] = 'READ RECORD', -- CLA value '0X' or '4X' or '6X'
    [0xdc] = 'UPDATE RECORD', -- CLA value '0X' or '4X' or '6X'
    [0xa2] = 'SEARCH RECORD', -- CLA value '0X' or '4X' or '6X'
    [0x32] = 'INCREASE', -- CLA value '8X' or 'CX' or 'EX'
    [0xcb] = 'RETRIEVE DATA', -- CLA value '8X' or 'CX' or 'EX'
    [0xdb] = 'SET DATA', -- CLA value '8X' or 'CX' or 'EX'
    [0x20] = 'VERIFY PIN', -- CLA value '0X' or '4X' or '6X'
    [0x24] = 'CHANGE PIN', -- CLA value '0X' or '4X' or '6X'
    [0x26] = 'DISABLE PIN', -- CLA value '0X' or '4X' or '6X'
    [0x28] = 'ENABLE PIN', -- CLA value '0X' or '4X' or '6X'
    [0x2c] = 'UNBLOCK PIN', -- CLA value '0X' or '4X' or '6X'
    [0x04] = 'DEACTIVATE FILE', -- CLA value '0X' or '4X' or '6X'
    [0x44] = 'ACTIVATE FILE', -- CLA value '0X' or '4X' or '6X'
    [0x88] = 'AUTHENTICATE', -- CLA value '0X' or '4X' or '6X'
    [0x89] = 'AUTHENTICATE', -- CLA value '0X' or '4X' or '6X'
    [0x84] = 'GET CHALLENGE', -- CLA value '0X' or '4X' or '6X'
    [0xaa] = 'TERMINAL CAPABILITY', -- CLA value '8X' or 'CX' or 'EX'
    [0x10] = 'TERMINAL PROFILE', -- CLA value '80'
    [0xc2] = 'ENVELOPE', -- CLA value '80'
    [0x12] = 'FETCH', -- CLA value '80'
    [0x14] = 'TERMINAL RESPONSE', -- CLA value '80'
    [0x70] = 'MANAGE CHANNEL', -- CLA value '0X' or '4X' or '6X'
    [0x73] = 'MANAGE SECURE CHANNEL', -- CLA value '0X' or '4X' or '6X'
    [0x75] = 'TRANSACT DATA', -- CLA value '0X' or '4X' or '6X'
    [0x76] = 'SUSPEND UICC', -- CLA value '80'
    [0x78] = 'GET IDENTITYCLAINS', -- CLA value '8X' or 'CX' or 'EX' (see note)
    [0x7a] = 'EXCHANGE CAPABILITIES', -- CLA value '80' (see note)
    --These INS values are also used by GlobalPlatform (for the commands END R-MAC SESSION and BEGIN R-MAC SESSION)

    -- Transmission oriented APDUs applying to the above commands
    [0xc0] = 'GET RESPONSE', -- CLA value '0X' or '4X' or '6X'
}

local p = Proto.new("iso7816.apdu.commands", "ISO7816-APDU commands")
local pf = {
    command = ProtoField.string(p.name .. ".command", "Command"),
    cla_coding = ProtoField.uint8(p.name .. ".cla.coding", "Class Coding",base.HEX, CLA_CODING, 0xf0),
    cla_secure_messaging_ind = ProtoField.uint8(p.name .. ".cla.secure_messaging_ind", "Secure Messaging Indication",base.HEX, SECURE_MESSAGING_INDICATOR, 0x0C),
    cla_log_chan = ProtoField.uint8(p.name .. ".cla.log_chan", "Logical Channel number",base.DEC, nil, 0x03),
    instruction = ProtoField.string(p.name .. ".ins", "Instruction"),
    p1 = ProtoField.uint8(p.name .. ".p1", "Parameter 1", base.HEX),
    p2 = ProtoField.uint8(p.name .. ".p2", "Parameter 2", base.HEX),
    le = ProtoField.uint8(p.name .. ".le", "APDU Payload Length (Parameter 3)", base.DEC),
    data = ProtoField.bytes(p.name .. ".data", "APDU Payload"),

    no_dissector = ProtoField.string(p.name .. ".no_dissector", "No dissector for command"),
}
p.fields = pf

local dt_commands = DissectorTable.new('iso7816.apdu.commands', 'ISO7816-APDU commands', ftypes.UINT8, base.HEX, p)
dt_commands:add(INSTRUCTIONS_CODE.SELECT, require('apdu_sub_dissectors/commands/SELECT'))
dt_commands:add(INSTRUCTIONS_CODE.GET_RESPONSE, require('apdu_sub_dissectors/commands/GET_RESPONSE'))
dt_commands:add(INSTRUCTIONS_CODE.READ_BINARY, require('apdu_sub_dissectors/commands/READ_BINARY'))
dt_commands:add(INSTRUCTIONS_CODE.READ_RECORD, require('apdu_sub_dissectors/commands/READ_RECORD'))
dt_commands:add(INSTRUCTIONS_CODE.UPDATE_BINARY, require('apdu_sub_dissectors/commands/UPDATE_BINARY'))
dt_commands:add(INSTRUCTIONS_CODE.UPDATE_RECORD, require('apdu_sub_dissectors/commands/UPDATE_RECORD'))

function p.dissector(buffer, pinfo, tree)

    local cla_f = buffer:range(0,1)
    local ins_f = buffer:range(1,1)
    local p1_f =  buffer:range(2,1)
    local p2_f =  buffer:range(3,1)
    local le_f = buffer:range(4,1)
    local le = le_f:uint()
    local data_f = buffer:range(5,le)
    local offset = 0
    offset = offset + 5

    local ins = ins_f:uint()
    local command_tree = tree:add(pf.command, buffer:range(0,5), string.format('%s (0x%2x)', INSTRUCTIONS[ins], ins))
    command_tree:add(pf.cla_coding, cla_f)
    command_tree:add(pf.cla_secure_messaging_ind, cla_f)
    command_tree:add(pf.cla_log_chan, cla_f)
    command_tree:add(pf.instruction, ins_f, string.format('%s (0x%2x)', INSTRUCTIONS[ins], ins))


    local command_dissector = dt_commands:get_dissector(ins)
    if command_dissector then
        pinfo.cols.protocol:append(' - APDU')
        offset = offset + command_dissector:call(buffer, pinfo, tree)
    else
        command_tree:add(pf.p1, p1_f)
        command_tree:add(pf.p2, p2_f)
        command_tree:add(pf.le, le_f)
        tree:add(pf.data, data_f)
        tree:add(pf.no_dissector, data_f, string.format('%s (0x%2x)', INSTRUCTIONS[ins], ins))
        print(string.format('frame: %s - No command dissector found for instruction: (0x%02x) - %s', pinfo.number, ins, INSTRUCTIONS[ins]))
        --tree:add(pf.no_dissector, ins_f, ins, string.format('No command dissector found for Instruction: (0x%02x) - %s', ins, INSTRUCTIONS[ins]))
    end
    return offset

end

return p -- returning protocol to add it into dissector table with require
