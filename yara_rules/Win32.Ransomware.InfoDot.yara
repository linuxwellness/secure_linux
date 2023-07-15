rule Win32_Ransomware_InfoDot : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "INFODOT"
        description         = "Yara rule that detects InfoDot ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "InfoDot"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B FA 8B D9 89 9D ?? ?? ?? ?? 
            68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? 53 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            50 8D 85 ?? ?? ?? ?? 50 FF D3 8B F0 83 FE ?? 0F 84 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? EB 
            ?? 8D 49 ?? F6 85 ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 
            ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 
            8D 85 ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 
            ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? 
            ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 
            ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 
            C0 74 ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B FF 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 
            ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 
            83 C8 ?? 85 C0 74 ?? 8D 85 ?? ?? ?? ?? 50 53 8D 85 ?? ?? ?? ?? 50 FF 15
        }

        $find_files_p2 = { 
            8B D7 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 
            C0 0F 85 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 57 8B 3D ?? ?? ?? ?? 56 50 FF D7 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 
            50 FF D3 89 85 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 8D 9B ?? ?? ?? ?? F6 85 ?? ?? 
            ?? ?? ?? 0F 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? 
            ?? 50 56 FF 15 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 56 8D 85 ?? ?? ?? ?? 50 FF D7 68 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 66 39 85 ?? ?? ?? ?? 75 ?? 33 C9 
            EB ?? 8D 8D ?? ?? ?? ?? 8D 51 ?? 90 66 8B 01 83 C1 ?? 66 85 C0 75 ?? 2B CA D1 F9 51 
            8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 8D ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 51 50 E8 ?? ?? ?? ?? 99 83 C4 ?? 0B 
            C2 75 ?? 8B 85 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? 83 CB ?? 83 BD ?? ?? ?? ?? ?? 72 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            83 C4 ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F8 BA ?? ?? ?? ?? 8B CF 8D A4 24 
            ?? ?? ?? ?? 66 8B 31 66 3B 32 75 ?? 66 85 F6 74 ?? 66 8B 41 ?? 66 3B 42 ?? 75 ?? 83
        }
            
        $find_files_p3 = {
            C1 ?? 83 C2 ?? 66 85 C0 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? B9 
            ?? ?? ?? ?? 8B C7 8D 9B ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 
            ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 
            C0 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B C7 8D 9B ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 
            66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 
            EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B C7 8D 9B ?? ?? ?? ?? 
            66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 
            ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 
            8B C7 8D 9B ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 
            ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? 
            ?? ?? ?? B8 ?? ?? ?? ?? 66 8B 0F 66 3B 08 75 ?? 66 85 C9 74 ?? 66 8B 4F ?? 66 3B 48 
            ?? 75 ?? 83 C7 ?? 83 C0 ?? 66 85 C9 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? 
            ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 85 DB 7F ?? 8B 95 ?? ?? ?? ?? 7C ?? 81
        }

        $find_files_p4 = {
            FA ?? ?? ?? ?? 73 ?? 3B D8 0F 8F ?? ?? ?? ?? 7C ?? 3B D1 73 ?? 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 83 EC ?? 8D 95 ?? ?? ?? ?? 8B CC 51 E8 ?? ?? ?? ?? 83 C4 ?? E8 ?? ?? ?? 
            ?? 83 C4 ?? 84 C0 74 ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 3B D8 7F 
            ?? 7C ?? 8B 85 ?? ?? ?? ?? 3B C1 73 ?? 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 50 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 
            8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? EB ?? 8B 85 ?? ?? ?? ?? 8B 3D ?? 
            ?? ?? ?? 8B B5 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 51 50 FF 15 ?? ?? ?? 
            ?? 85 C0 8B 85 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 64 89 0D 
            ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $encrypt_files = {
            55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 56 8B F1 C7 85 
            ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 85 C0 74 ?? 83 C8 ?? 5E 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 56 8D 85 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 0F 57 
            C0 68 ?? ?? ?? ?? 50 F3 0F 7F 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? 
            ?? ?? ?? 50 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 
            57 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 8B FF 
            81 FF ?? ?? ?? ?? 75 ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 57 50 
            50 E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 57 6A ?? 50 E8 ?? ?? ?? ?? FF 
            B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 57 6A ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 75 
            ?? 8B C7 25 ?? ?? ?? ?? 79 ?? 48 83 C8 ?? 40 BE ?? ?? ?? ?? 2B F0 8D 85 ?? ?? ?? ?? 
            56 03 C7 56 50 E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 03 F7 8D 85 ?? ?? 
            ?? ?? 56 50 50 E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 56 6A ?? 50 E8 ?? 
            ?? ?? ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D ?? 
            83 C4 ?? 33 CD 33 C0 5F 5E E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_p*) 
        ) and
        (
            $encrypt_files
        )
}