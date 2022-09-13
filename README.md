# Wireshark - APDU Payload Dissector
This dissector for wireshark attempts to decode the APDU payload, that is so far not parsed by the built in 'gsm_sim' dissector.
In the initial version, there is support for the following scenarios:
 
   - `FILE SELECT -> GET RESPONSE -> READ BINARY`
     - `FILE SELECT` will be recognized, selected file is stored in conversation info
     - `GET RESPONSE` will be parsed according to specification 
       *ETSI TS 102 221 V17.1.0 (2022-02) - Smart Cards / UICC-Terminal interface / Physical and logical characteristics*
     - `READ BINARY` selected file (if reference) will be parsed. The parser is selected according to previously selected file. As example ICCID nibble swap is provided.

## INSTALLATION

1. download this repo into a `project folder`
2. find the `script folder` in your `wireshark ui -> about -> folders` dialog
3. copy `iso7816_apdu.lua` and the `iso7816_apdu` folder from the `project folder` into the `script folder`

Alternative: don't install, run the plugin via cli parameter from the `project folder`
- either run the provided shell script `wireshark_iso7816.sh` (change `pcapng` file accordingly)
- or call wireshark manually `wireshark -X lua_script:iso7816_apdu.lua -r your.pcapng`

## USAGE

- if installed, the plugin will automatically be loaded on start of wireshark
- if not installed, run wireshark from command line in the `project folder` or use the provided shell script `wireshark_iso7816.sh` (change `pcapng` file accordingly)

## HOW IT WORKS 

The example flow of `SELECT -> GET RESPONSE -> READ BINARY` includes the following:
1. `SELECT`
   1. The main dissector `iso7816_apdu.lua` stores the selected file id and expected response length
2. `GET RESPONSE`
   1. `iso7816_apdu.lua` checks if the buffer length matches the previous `SELECT` and will store conversation data
   2. `iso7816_apdu.lua` will call `dissect_remaining_tlvs` with a `DissectorTable` as parameter
   3. `dissect_remaining_tlvs` extracts the first byte of the given data buffer (tlv-tag) and uses it as key to find a matching sub-dissector
   4. the sub-dissector will parse the according tlv section of the data and add tree elements to the wireshark ui output
   5. if the sub-dissectors find data that points to a required followup `READ BINARY` or `READ RECORD` to read a file reference, they will store relevant data.
3. `READ BINARY`
   1. `iso7816_apdu.lua` checks if the sub-dissectors of the previous `GET RESPONSE` left conversation data that matches this commands data
   2. `iso7816_apdu.lua` will call `dissect_file_content` with a `DissectorTable` as parameter
   3. `dissect_file_content` extracts the selected file from the conversation data of the previous `SELECT` and uses it as key to find a matching sub-dissector
   4. the sub-dissector will parse the file data and add tree elements to the wireshark ui output
   5. if the sub-dissectors find data that points to a required followup `READ BINARY` or `READ RECORD` to read a file reference, they will store relevant data.
      TODO: this currently works only without interruption packets between the read packets

## EXTENSION
The `GET RESPONSE` command holds an APDU payload with `0x62` in the first byte, which is documented as `FCP Template` in [**ETSI TS 102 221**](https://standards.iteh.ai/catalog/standards/etsi/92ca5ef0-9ca6-4798-a250-32d501a96aaa/etsi-ts-102-221-v17-1-0-2022-02)

For other commands the APDU payload will be different, indicated by a different first byte. 
To add a dissector for them 
- either copy a simple dissector like `apdu_sub_dissectors/fcp_template/file_size_total.lua` 
- or a more complex one with sub-dissectors like `apdu_sub_dissectors/fcp_template.lua` 
- and register it in `iso7816_apdu.lua`'s DissectorTable.
