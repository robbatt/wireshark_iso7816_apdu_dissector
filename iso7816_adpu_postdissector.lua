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

-- Step 3 - add some field(s) to Step 2 protocol
local pf = {
    data = ProtoField.bytes(p.name .. ".data", "Data"),
}
p.fields = pf

-- Step 4 - create a Field extractor to copy packet field data.
iso7816_apdu_data_f = Field.new('gsm_sim.apdu.data')

-- Step 5 - create the postdissector function that will run on each frame/packet
function p.dissector(tvb, pinfo, tree)
    -- copy already processed field(s)
    local apdu_payload = iso7816_apdu_data_f()

    if apdu_payload then
        -- override protocol column
        pinfo.cols.protocol:append(' - APDU')

        -- this will call the according sub-dissector for each section
        local buffer = apdu_payload.tvb
        local subtree = tree:add(p, buffer, 'Iso7816 APDU Data')
        subtree:add(pf.data, buffer)
    end
    return tvb:len()
end

-- Step 6 - register the new protocol as a postdissector
register_postdissector(p)