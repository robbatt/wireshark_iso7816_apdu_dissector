
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

dt_file_parsers = DissectorTable.new('iso7816.apdu.file_parsers', 'ISO7816-APDU file parsers', ftypes.UINT8, base.HEX, p)
dt_file_parsers:add(0x2fe2, require('apdu_sub_dissectors/file_parsers/ICCID'))
dt_file_parsers:add(0x6f07, require('apdu_sub_dissectors/file_parsers/IMSI'))
dt_file_parsers:add(0x6f7e, require('apdu_sub_dissectors/file_parsers/LOCI'))
dt_file_parsers:add(0x6f73, require('apdu_sub_dissectors/file_parsers/PSLOCI'))
dt_file_parsers:add(0x6fe3, require('apdu_sub_dissectors/file_parsers/EPSLOCI'))
dt_file_parsers:add(0x6f62, require('apdu_sub_dissectors/file_parsers/HPLMNwAcT'))
dt_file_parsers:add(0x6f61, require('apdu_sub_dissectors/file_parsers/OPLMNwAcT'))
dt_file_parsers:add(0x6f7b, require('apdu_sub_dissectors/file_parsers/FPLMN'))
dt_file_parsers:add(0x6f31, require('apdu_sub_dissectors/file_parsers/HPPLMN'))

dt_record_parsers = DissectorTable.new('iso7816.apdu.record_parsers', 'ISO7816-APDU record parsers', ftypes.UINT8, base.HEX, p)
dt_record_parsers:add(0x6fb7, require('apdu_sub_dissectors/record_parsers/ECC'))
dt_record_parsers:add(0x6f40, require('apdu_sub_dissectors/record_parsers/MSISDN'))