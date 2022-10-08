
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

STATUS_CODE = {
    NORMAL_ENDING = 0x90,
    RESPONSE_READY = 0x61,
    ERROR = 0x62,
}

-- ETSI TS 102 221 V17.1.0 (2022-02) - 10.2.1 Status conditions returned by the UICC
STATUS = {
    -- Table 10.7: Status byte coding - normal processing
    [0x90] = 'Normal ending of the command',
    [0x91] = 'Normal ending of the command, with extra information from the proactive UICC containing a command for the terminal. Response data length is',
    [0x92] = 'Normal ending of the command, with extra information concerning an ongoing data transfer session',

    --Table 10.9: Status byte coding - warnings
    [0x61] = 'Response ready, Response length is',

    --Table 10.9: Status byte coding - warnings
    [0x62] = 'Warning',

    --Table 10.14: Status byte coding - wrong parameters
    [0x6a] = 'Wrong parameters',
    [0x6c] = 'Terminal should repeat command, Length for repeated command is',
}

STATUS_CODE_DETAILS = {
    [0x62] = STATUS_DETAIL_62_WARNINGS,
    [0x6a] = STATUS_DETAIL_6A_WRONG_PARAMETERS
}

STATUS_DETAIL_6A_WRONG_PARAMETERS = {
    [0x80] = 'Incorrect parameters in the data field',
    [0x81] = 'Function not supported',
    [0x82] = 'File not found',
    [0x83] = 'Record not found',
    [0x84] = 'Not enough memory space',
    [0x86] = 'Incorrect parameters P1 to P2',
    [0x87] = 'Lc inconsistent with P1 to P2',
    [0x88] = 'Referenced data not found'
}

STATUS_DETAIL_62_WARNINGS = {
    [0x00] = 'No information given, state of non-volatile memory unchanged',
    [0x81] = 'Part of returned data may be corrupted',
    [0x82] = 'End of file/record reached before reading Le bytes or unsuccessful search',
    [0x83] = 'Selected file invalidated',
    [0x85] = 'Selected file in termination state',
    [0xF1] = 'More data available',
    [0xF2] = 'More data available and proactive command pending',
    [0xF3] = 'Response data available',
}


local p = Proto.new("iso7816.apdu.status", "ISO7816-APDU status")
local pf = {
    status = ProtoField.uint16(p.name .. ".sw", "Status Word", base.HEX),
}
p.fields = pf

function p.dissector(buffer, pinfo, tree)
    local offset = 0
    local sw_f = buffer:range(0,2)
    local sw1 = sw_f:range(0,1):uint() -- status 61: response ready, 90: normal end
    local sw2 = sw_f:range(1,1):uint() -- expected response length
    offset = offset + 2

    local sw2map = STATUS_CODE_DETAILS[sw1]
    local sw2detailCode = sw2map and sw2map[sw2]
    local sw2detailLength = sw2 > 0 and sw2
    local sw2detail = sw2detailCode or sw2detailLength or ''

    tree:add(pf.status, sw_f, sw_f:uint(), string.format('Status Word: (0x%4x) %s %s', sw_f:uint(), STATUS[sw1], sw2detail))

    return offset
end

return p -- returning protocol to add it into dissector table with require
