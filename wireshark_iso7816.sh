#! /bin/bash

wireshark -X lua_script:iso7816_adpu.lua -r simtrace2_bg95_boot_roam_profile.pcapng
