#! /bin/bash

#wireshark -X lua_script:register_iso7816_adpu_postdissector.lua -r iso7816_example.pcapng
wireshark -X lua_script:iso7816_adpu_postdissector.lua -r simtrace2_bg95_boot_roam_profile.pcapng
