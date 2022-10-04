
-- prevent wireshark loading this file as a plugin
if not _G['iso7816_apdu'] then return end

YES_NO = {
    [0] = "No",
    [1] = "Yes"
}

INSTRUCTIONS = {
    [0xa4] = 'SELECT',
    [0xc0] = 'GET RESPONSE',
    [0xb0] = 'READ BINARY',
    [0xb2] = 'READ RECORD',
}

FILE_IDENTIFIERS = {
    [0x3F00] = 'MF',
    [0x2F00] = 'EF.DIR',
    [0x2F05] = 'EF.PL',
    [0x2F06] = 'EF.APR',
    [0x2FE2] = 'EF.ICCID',
    [0x2F08] = 'EF.UMPC',

    -- ADF.USIM
    [0x6F05] = 'EF.LI',
    [0x6F06] = 'EF.ARR',
    [0x6F07] = 'EF.IMSI',
    [0x6F08] = 'EF.Keys',
    [0x6F09] = 'EF.KeysPS',
    [0x6F2C] = 'EF.DCK',
    [0x6F31] = 'EF.HPPLMN',
    [0x6F32] = 'EF.CNL',
    [0x6F37] = 'EF.ACMmax',
    [0x6F38] = 'EF.UST',
    [0x6F39] = 'EF.ACM',
    [0x6F3B] = 'EF.FDN',
    [0x6F3C] = 'EF.SMS',
    [0x6F3E] = 'EF.GID1',
    [0x6F3F] = 'EF.GID2',
    [0x6F40] = 'EF.MSISDN',
    [0x6F41] = 'EF.PUCT',
    [0x6F42] = 'EF.SMSP',
    [0x6F43] = 'EF.SMSS',
    [0x6F45] = 'EF.CBMI',
    [0x6F46] = 'EF.SPN',
    [0x6F47] = 'EF.SMSR',
    [0x6F48] = 'EF.CBMID',
    [0x6F49] = 'EF.SDN',
    [0x6F4B] = 'EF.EXT2',
    [0x6F4C] = 'EF.EXT3',
    [0x6F4D] = 'EF.BDN',
    [0x6F4E] = 'EF.EXT5',
    [0x6F4F] = 'EF.CCP2',
    [0x6F50] = 'EF.CBMIR',
    [0x6F55] = 'EF.EXT4',
    [0x6F56] = 'EF.EST',
    [0x6F57] = 'EF.ACL',
    [0x6F58] = 'EF.CMI',
    [0x6F5B] = 'EF.START-HFN',
    [0x6F5C] = 'EF.THRESHOLD',
    [0x6F60] = 'EF.PLMNwAcT',
    [0x6F61] = 'EF.OPLMNwAcT',
    [0x6F62] = 'EF.HPLMNwAcT',
    [0x6F73] = 'EF.PSLOCI',
    [0x6F78] = 'EF.ACC',
    [0x6F7B] = 'EF.FPLMN',
    [0x6F7E] = 'EF.LOCI',
    [0x6F80] = 'EF.ICI',
    [0x6F81] = 'EF.OCI',
    [0x6F82] = 'EF.ICT',
    [0x6F83] = 'EF.OCT',
    [0x6FAD] = 'EF.AD',
    [0x6FB1] = 'EF.VGCS',
    [0x6FB2] = 'EF.VGCSS',
    [0x6FB3] = 'EF.VBS',
    [0x6FB4] = 'EF.VBSS',
    [0x6FB5] = 'EF.eMLPP',
    [0x6FB6] = 'EF.AaeM',
    [0x6FB7] = 'EF.ECC',
    [0x6FC3] = 'EF.Hiddenkey',
    [0x6FC4] = 'EF.NETPAR',
    [0x6FC5] = 'EF.PNN',
    [0x6FC6] = 'EF.OPL',
    [0x6FC7] = 'EF.MBDN',
    [0x6FC8] = 'EF.EXT6',
    [0x6FC9] = 'EF.MBI',
    [0x6FCA] = 'EF.MWIS',
    [0x6FCB] = 'EF.CFIS',
    [0x6FCC] = 'EF.EXT7',
    [0x6FCD] = 'EF.SPDI',
    [0x6FCE] = 'EF.MMSN',
    [0x6FCF] = 'EF.EXT8',
    [0x6FD0] = 'EF.MMSICP',
    [0x6FD1] = 'EF.MMSUP',
    [0x6FD2] = 'EF.MMSUCP',
    [0x6FD3] = 'EF.NIA',
    [0x6FD4] = 'EF.VGCSCA',
    [0x6FD5] = 'EF.VBSCA',
    [0x6FD6] = 'EF.GBAP',
    [0x6FD7] = 'EF.MSK',
    [0x6FD8] = 'EF.MUK',
    [0x6FD9] = 'EF.EHPLMN',
    [0x6FDA] = 'EF.GBANL',
    [0x6FDB] = 'EF.EHPLMNPI',
    [0x6FDC] = 'EF.LRPLMNSI',
    [0x6FDD] = 'EF.NAFKCA',
    [0x6FDE] = 'EF.SPNI',
    [0x6FDF] = 'EF.PNNI',
    [0x6FE2] = 'EF.NCP-IP',
    [0x6FE3] = 'EF.EPSLOCI',
    [0x6FE4] = 'EF.EPSNSC',
    [0x6FE6] = 'EF.UFC',
    [0x6FE7] = 'EF.UICCIARI',
    [0x6FE8] = 'EF.NASCONFIG',
    [0x6FEC] = 'EF.PWS',
    [0x6FED] = 'EF.FDNURI',
    [0x6FEE] = 'EF.BDNURI',
    [0x6FEF] = 'EF.SDNURI',
    [0x6FF0] = 'EF.IWL',
    [0x6FF1] = 'EF.IPS',
    [0x6FF2] = 'EF.IPD',
    [0x6FF3] = 'EF.ePDG.Id',
    [0x6FF4] = 'EF.ePDG.Selection',
    [0x6FF5] = 'EF.ePDGIdEm',
    [0x6FF6] = 'EF.ePDGSelectionEm',
    [0x6FF7] = 'EF.FromPreferred',
    [0x6FF8] = 'EF.IMSConfigData',
    [0x6FF9] = 'EF.3GPPPSDATA.OFF',
    [0x6FFA] = 'EF.3GPPPSDATA.OFFservicelist',
    [0x6FFB] = 'EF.TVCONFIG',
    [0x6FFC] = 'EF.XCAPConfigData',
    [0x6FFE] = 'EF.EARFCNList',
    [0x6FFF] = 'EF.5GSLOCI',
    [0x6F00] = 'EF.5GS3GPPNSC',
    [0x6F01] = 'EF.5GSN3GPPNS',
    [0x6F05] = 'EF.Steering_of_UCE_in_VPLMN',

    [0x5F3A] = 'DF.PHONEBOOK',
    [0x4F22] = 'EF.PSC',
    [0x4F23] = 'EF.CC',
    [0x4F24] = 'EF.PUID',
    [0x4F30] = 'EF.PBR',
    --[0x4FXX] = 'EF.UID',
    --[0x4FXX] = 'EF.CCP1',
    --[0x4FXX] = 'EF.IAP',
    --[0x4FXX] = 'EF.ADN',
    --[0x4FXX] = 'EF.EXT1',
    --[0x4FXX] = 'EF.PBC',
    --[0x4FXX] = 'EF.GRP',
    --[0x4FXX] = 'EF.AAS',
    --[0x4FXX] = 'EF.GAS',
    --[0x4FXX] = 'EF.ANR',
    --[0x4FXX] = 'EF.SNE',
    --[0x4FXX] = 'EF.EMAIL',
    --[0x4FXX] = 'EF.PURI',

    [0x5F3B] = 'DF.GSM-ACCESS',
    [0x4F20] = 'EF.Kc',
    [0x4F52] = 'EF.KcGPRS',
    [0x4F63] = 'EF.CPBCCH',
    [0x4F64] = 'EF.invSCAN',

    [0x5F3B] = 'DF.MULTIMEDIA',
    [0x4F47] = 'EF.MML',
    [0x4F48] = 'EF.MMDF',


    [0x5F3C] = 'DF.MexE',
    [0x4F40] = 'EFMexE-ST.',
    [0x4F41] = 'EF.ORPK',
    [0x4F42] = 'EF.ARPK',
    [0x4F43] = 'EF.TPRK',
    --[0x4FXX] = 'EF.TKCDF',

    [0x5F70] = 'DF.SoLSA',
    [0x4F30] = 'EF.SAI',
    [0x4F31] = 'EF.SLL',

    [0x5F40] = 'DF.WLAN',
    [0x4F41] = 'EF.Pseudo',
    [0x4F42] = 'EF.UPLMNWLAN',
    [0x4F43] = 'EF.0PLMNWLAN',
    [0x4F44] = 'EF.UWSIDL',
    [0x4F45] = 'EF.OWSIDL',
    [0x4F46] = 'EF.WRI',
    [0x4F47] = 'EF.HWSIDL',
    [0x4F48] = 'EF.WEHPLMNPI',
    [0x4F49] = 'EF.WHPI',
    [0x4F4A] = 'EF.WLRPLMN',
    [0x4F4B] = 'EF.HPLMNDAI',

    [0x5F50] = 'DF.HNB',
    [0x4F81] = 'EF.ACSGL',
    [0x4F82] = 'EF.CSGT',
    [0x4F83] = 'EF.HNBN',
    [0x4F84] = 'EF.OCSGL',
    [0x4F85] = 'EF.OCSGT',
    [0x4F86] = 'EF.OHNBN',

    [0x5F90] = 'DF.ProSe',
    [0x4F01] = 'EF.PROSE_MON',
    [0x4F02] = 'EF.PROSE_ANN',
    [0x4F03] = 'EF.PROSEFUNC',
    [0x4F04] = 'EF.PROSE_RADIO_COM',
    [0x4F05] = 'EF.PROSE_RADIO_MON',

    [0x4F06] = 'EF.PROSE_RADIO_ANN',
    [0x4F07] = 'EF.PROSE_POLICY',
    [0x4F08] = 'EF.PROSE_PLMN',
    [0x4F09] = 'EF.PROSE_GC',
    [0x4F10] = 'EF.PST',
    [0x4F11] = 'EF.PROSE_UIRC',
    [0x4F12] = 'EF.PROSE_GM_DISCOVERY',
    [0x4F13] = 'EF.PROSE_RELAY',
    [0x4F14] = 'EF.PROSE_RELAY_DISCOVERY',

    [0x5FA0] = 'DF.ACDC',
    [0x4F01] = 'EF.ACDC_LIST',
    --[0x4FXX] = 'EF.ACDC_OS_CONFIG',

    [0x5FB0] = 'DF.TV',
    --[0x4FXX] = 'EF.TVUSD',

    [0x5FC0] = 'DF.5GS',
    [0x4F01] = 'EF.5GS3GPPLOCI',
    [0x4F02] = 'EF.5GSN3GPPLOCI',
    [0x4F06] = 'EF.UAC_AIC',
    [0x4F07] = 'EF.SUCI_Calc_Inf',

    [0x4F03] = 'EF.5GS3GPPNSC',
    [0x4F04] = 'EF.5GSN3GPPNSC',
    [0x4F05] = 'EF.5GAUTHKEYS',

    [0x7FFF] = 'ADF',
}

--H.1 List of SFI Values at the USIM ADF Level

SFI_FILE_MAPPING = {
    [0x01] = 0x6FB7,  -- Emergency call codes
    [0x02] = 0x6F05,  -- Language indication
    [0x03] = 0x6FAD,  -- Administrative data
    [0x04] = 0x6F38,  -- USIM service table
    [0x05] = 0x6F56,  -- Enabled services table
    [0x06] = 0x6F78,  -- Access control class
    [0x07] = 0x6F07,  -- IMSI
    [0x08] = 0x6F08,  -- Ciphering and integrity keys
    [0x09] = 0x6F09,  -- Ciphering and integrity keys for packet switched domain
    [0x0A] = 0x6F60,  -- User PLMN selector
    [0x0B] = 0x6F7E,  -- Location information
    [0x0C] = 0x6F73,  -- Packet switched location information
    [0x0D] = 0x6F7B,  -- Forbidden PLMNs
    [0x0E] = 0x6F48,  -- CBMID
    [0x0F] = 0x6F5B,  -- Hyperframe number
    [0x10] = 0x6F5C,  -- Maximum value of hyperframe number
    [0x11] = 0x6F61,  -- Operator PLMN selector
    [0x12] = 0x6F31,  -- Higher Priority PLMN search period
    [0x13] = 0x6F62,  -- Preferred HPLMN access technology
    [0x14] = 0x6F80,  -- Incoming call information
    [0x15] = 0x6F81,  -- Outgoing call information
    [0x16] = 0x6F4F,  -- Capability configuration parameters 2
    [0x17] = 0x6F06,  -- Access Rule Reference
    [0x19] = 0x6FC5,  -- PLMN Network Name
    [0x1A] = 0x6FC6,  -- Operator Network List
    [0x1B] = 0x6FCD,  -- Service Provider Display Information
    [0x1C] = 0x6F39,  -- Accumulated Call Meter (see note)
    [0x1D] = 0x6FD9,  -- Equivalent HPLMN
    [0x1E] = 0x6FE3,  -- EPS location information
    [0x18] = 0x6FE4,  -- EPS NAS Security Context
}
SFI_FILE_IDENTIFIERS = {
    [0x01] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x01]],  -- Emergency call codes
    [0x02] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x02]],  -- Language indication
    [0x03] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x03]],  -- Administrative data
    [0x04] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x04]],  -- USIM service table
    [0x05] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x05]],  -- Enabled services table
    [0x06] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x06]],  -- Access control class
    [0x07] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x07]],  -- IMSI
    [0x08] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x08]],  -- Ciphering and integrity keys
    [0x09] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x09]],  -- Ciphering and integrity keys for packet switched domain
    [0x0A] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x0A]],  -- User PLMN selector
    [0x0B] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x0B]],  -- Location information
    [0x0C] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x0C]],  -- Packet switched location information
    [0x0D] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x0D]],  -- Forbidden PLMNs
    [0x0E] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x0E]],  -- CBMID
    [0x0F] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x0F]],  -- Hyperframe number
    [0x10] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x10]],  -- Maximum value of hyperframe number
    [0x11] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x11]],  -- Operator PLMN selector
    [0x12] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x12]],  -- Higher Priority PLMN search period
    [0x13] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x13]],  -- Preferred HPLMN access technology
    [0x14] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x14]],  -- Incoming call information
    [0x15] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x15]],  -- Outgoing call information
    [0x16] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x16]],  -- Capability configuration parameters 2
    [0x17] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x17]],  -- Access Rule Reference
    [0x19] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x19]],  -- PLMN Network Name
    [0x1A] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x1A]],  -- Operator Network List
    [0x1B] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x1B]],  -- Service Provider Display Information
    [0x1C] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x1C]],  -- Accumulated Call Meter (see note)
    [0x1D] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x1D]],  -- Equivalent HPLMN
    [0x1E] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x1E]],  -- EPS location information
    [0x18] = FILE_IDENTIFIERS[SFI_FILE_MAPPING[0x18]],  -- EPS NAS Security Context
}