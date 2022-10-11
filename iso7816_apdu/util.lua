
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

function dissect_response_tlvs(buffer, pinfo, tree, protocol, dissector_table)
    local offset = 0
    local length = buffer:len()
    while (offset < length) do
        local tlv_tag = buffer(offset, 1):uint()
        local tlv_dissector = dissector_table:get_dissector(tlv_tag)
        local tlv_length = 2 + buffer(offset + 1, 1):uint()

        local consumed_bytes = tlv_length
        if tlv_dissector then
            consumed_bytes = tlv_dissector:call(buffer(offset, tlv_length):tvb(), pinfo, tree)
        else
            print(string.format('frame: %s - No tlv-dissector found for tag: 0x%02x in dissector: %s', pinfo.number, tlv_tag, protocol.name))
        end
        offset = offset + consumed_bytes
    end
    return offset
end

function dissect_file_content(buffer, pinfo, tree, protocol, dissector_table, file_id)
    if not file_id then
        return 0
    end
    local parser = dissector_table:get_dissector(file_id)
    if parser then
        --print(string.format('frame: %s - found a file/record parser for file: 0x%02x - %s - in dissector: %s', pinfo.number, file_id, FILE_IDENTIFIERS[file_id], protocol.name))
        return parser:call(buffer():tvb(), pinfo, tree)
    else
        print(string.format('frame: %s - No file/record parser found for file: 0x%02x - %s - in dissector: %s', pinfo.number, file_id, FILE_IDENTIFIERS[file_id], protocol.name))
        return 0
    end
end

function deepcopy(o, seen)
    seen = seen or {}
    if o == nil then
        return nil
    end
    if seen[o] then
        return seen[o]
    end

    local no = {}
    seen[o] = no
    setmetatable(no, deepcopy(getmetatable(o), seen))

    for k, v in next, o, nil do
        k = (type(k) == 'table') and deepcopy(k, seen) or k
        v = (type(v) == 'table') and deepcopy(v, seen) or v
        no[k] = v
    end
    return no
end

function table.safe_get(table, key, default)
    for k, v in pairs(table) do
        if k == key then
            return v
        end
    end
    return default
end