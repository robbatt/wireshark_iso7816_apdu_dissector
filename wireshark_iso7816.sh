#! /bin/bash

wireshark -X lua_script:iso7816_apdu.lua -r reference_traces/simtrace2_bg95_boot_roam_profile.pcapng
