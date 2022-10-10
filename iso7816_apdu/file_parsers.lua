
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

dt_parsers = DissectorTable.new('iso7816.apdu.file_parsers', 'ISO7816-APDU file parsers', ftypes.UINT8, base.HEX, p)
dt_parsers:add(0x2fe2, require('apdu_sub_dissectors/file_parsers/ICCID'))
dt_parsers:add(0x6f07, require('apdu_sub_dissectors/file_parsers/IMSI'))
dt_parsers:add(0x6f7e, require('apdu_sub_dissectors/file_parsers/LOCI'))
dt_parsers:add(0x6f73, require('apdu_sub_dissectors/file_parsers/PSLOCI'))
dt_parsers:add(0x6fe3, require('apdu_sub_dissectors/file_parsers/EPSLOCI'))
dt_parsers:add(0x6f62, require('apdu_sub_dissectors/file_parsers/HPLMNwAcT'))
dt_parsers:add(0x6f61, require('apdu_sub_dissectors/file_parsers/OPLMNwAcT'))
dt_parsers:add(0x6f7b, require('apdu_sub_dissectors/file_parsers/FPLMN'))
dt_parsers:add(0x6f31, require('apdu_sub_dissectors/file_parsers/HPPLMN'))
