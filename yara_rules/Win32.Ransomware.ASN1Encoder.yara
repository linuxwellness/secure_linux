rule Win32_Ransomware_ASN1Encoder : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "ASN1ENCODER"
        description         = "Yara rule that detects ASN1Encoder ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "ASN1Encoder"
        tc_detection_factor = 5

    strings:

        $remote_connection_p1 = {
            68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 33 F6 0F B6 
            84 34 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? 2B C6 68 ?? ?? ?? ?? 03 C0 50 53 E8 ?? ?? ?? ?? 
            83 C4 ?? 83 C3 ?? 46 83 FE ?? 72 ?? 8B 5C 24 ?? BE ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 50 
            68 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 ?? 50 68 ?? ?? ?? ?? 56 50 
            E8 ?? ?? ?? ?? 33 C0 83 C4 ?? 8B F0 85 FF 74 ?? A1 ?? ?? ?? ?? 0F B6 04 06 50 B8 ?? 
            ?? ?? ?? 2B C6 68 ?? ?? ?? ?? 03 C0 50 53 E8 ?? ?? ?? ?? 83 C4 ?? 83 C3 ?? 46 3B F7 
            72 ?? 8B 5C 24 ?? A1 ?? ?? ?? ?? BE ?? ?? ?? ?? 53 50 68 ?? ?? ?? ?? 56 50 E8 ?? ?? 
            ?? ?? A1 ?? ?? ?? ?? 83 C4 ?? 50 68 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? 8D 8C 24 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? BA ?? ?? ?? ?? C1 E8 ?? 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 8D 94 24 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 8B FB 8B F0 0F B6 
            84 34 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? 2B C6 68 ?? ?? ?? ?? 03 C0 50 57 E8 ?? ?? ?? ?? 
            83 C4 ?? 83 C7 ?? 46 83 FE ?? 72 ?? A1 ?? ?? ?? ?? 53 50 68 ?? ?? ?? ?? BB ?? ?? ?? 
            ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 84 24 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 50 68 ?? ?? 
            ?? ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 84 24 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 50 68 ?? 
            ?? ?? ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 84 24 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 50 68 
            ?? ?? ?? ?? 53 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 83 C4 ?? 33 F6 8D 51 ?? 66 8B 01 
            83 C1 ?? 66 3B C6 75 ?? 2B CA 8B 15 ?? ?? ?? ?? D1 F9 8D 72 ?? 8A 02 42 84 C0 75 ?? 
            8B 3D ?? ?? ?? ?? 2B D6 8D 04 0A 8D 34 45 ?? ?? ?? ?? 56 6A ?? FF D7 50 FF 15 ?? ?? 
            ?? ?? 8B D8 8D 04 36 50 6A ?? 89 5C 24 ?? FF D7 50 FF 15 ?? ?? ?? ?? FF 35 ?? ?? ?? 
            ?? 8B F8 FF 35 ?? ?? ?? ?? 89 7C 24 ?? 68 ?? ?? ?? ?? 56 53 E8 ?? ?? ?? ?? 33 C9 89
        }

        $remote_connection_p2 = {
            44 24 ?? 83 C4 ?? 89 8C 24 ?? ?? ?? ?? 8B D9 85 C0 7E ?? 8B 44 24 ?? 0F B7 04 58 66 
            89 84 24 ?? ?? ?? ?? 83 F8 ?? 75 ?? 83 EF ?? 66 8B 47 ?? 83 C7 ?? 66 3B C1 75 ?? BE 
            ?? ?? ?? ?? 83 C3 ?? A5 A5 66 A5 EB ?? 8D 94 24 ?? ?? ?? ?? 8B F2 66 8B 02 83 C2 ?? 
            66 3B C1 75 ?? 2B D6 83 EF ?? 66 8B 47 ?? 83 C7 ?? 66 3B C1 75 ?? 8B CA C1 E9 ?? F3 
            A5 8B CA 83 E1 ?? F3 A4 33 C9 8B 7C 24 ?? 43 3B 5C 24 ?? 7C ?? FF 74 24 ?? 51 FF 15 
            ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 50 FF D6 FF 35 ?? ?? ?? ?? 33 C0 50 FF 15 ?? ?? ?? ?? 
            50 FF D6 8B 5C 24 ?? 53 33 DB 53 FF 15 ?? ?? ?? ?? 50 FF D6 FF 74 24 ?? 53 FF 15 ?? 
            ?? ?? ?? 50 FF D6 FF 74 24 ?? 53 FF 15 ?? ?? ?? ?? 50 FF D6 8B 5C 24 ?? 89 3D ?? ?? 
            ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 FF E9 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 
            83 F8 ?? 0F 84 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 57 
            FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 89 44 24 ?? 85 C0 
            0F 84 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B D8 8B F3 89 5C 24 ?? 8D 4E ?? 8A 06 46 84 
            C0 75 ?? 8B 3D ?? ?? ?? ?? 2B F1 68 ?? ?? ?? ?? 6A ?? FF D7 50 FF 15 ?? ?? ?? ?? 89 
            44 24 ?? 85 DB 0F 84 ?? ?? ?? ?? 81 FE ?? ?? ?? ?? 0F 82 ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            6A ?? FF D7 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 44 24 ?? 8D 84 24 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? 
            ?? ?? BA ?? ?? ?? ?? C1 E8 ?? 50 E8 ?? ?? ?? ?? 59 8D 94 24 ?? ?? ?? ?? 8D 8C 24 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 8B C8 8B F8 3B FE 73 ?? 81 F9 ?? ?? ?? ?? 74 ?? FF 74 
            24 ?? 8D 84 24 ?? ?? ?? ?? 50 8D 04 1F 50 E8 
        }

        $encrypt_files_p1 = {
            8B CA 8D 84 24 ?? ?? ?? ?? C1 E9 ?? F3 A5 53 68 ?? ?? ?? ?? 6A ?? 53 6A ?? 8B CA 83 
            E1 ?? 68 ?? ?? ?? ?? F3 A4 50 FF 15 ?? ?? ?? ?? 8B D8 33 FF 89 5C 24 ?? 89 3D ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? C7 44 
            24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 83 FB ?? 74 ?? 85 DB 0F 85 ?? ?? ?? ?? 33 
            F6 8D 8C 24 ?? ?? ?? ?? 8B DE E8 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? BE ?? ?? ?? ?? 50 
            8D 44 24 ?? 8B D6 50 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 59 8B CE E8 ?? ?? ?? ?? 33 D2 
            8D 88 ?? ?? ?? ?? 8D 81 ?? ?? ?? ?? 89 4C 24 ?? 89 44 24 ?? 8B 44 24 ?? C1 E8 ?? 89 
            44 24 ?? 83 C0 ?? 89 44 24 ?? 8B F0 8B C1 F7 F6 40 0F AF 44 24 ?? 50 6A ?? 89 44 24 
            ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? FF 74 24 ?? 89 44 24 ?? 6A ?? FF 15 ?? ?? 
            ?? ?? 50 FF 15 ?? ?? ?? ?? FF 74 24 ?? 89 44 24 ?? 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 89 44 24 ?? E8 ?? ?? ?? ?? 8B 54 24 ?? 
            8D 44 24 ?? 83 C4 ?? 81 C2 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 8D 8C 24 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 39 5C 24 ?? 76 ?? 8B 44 24 ?? 8D 
            54 24 ?? 8B 4C 24 ?? 2B C3 3B 44 24 ?? 0F 42 F0 8D 84 24 ?? ?? ?? ?? 50 8B 44 24 ?? 
            8D 0C 39 68 ?? ?? ?? ?? 03 C3 56 50 E8 ?? ?? ?? ?? 03 7C 24 ?? 83 C4 ?? 03 DE 3B 7C 
            24 ?? 72 ?? 33 FF 8D 84 24 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 6A ?? 57 6A ?? 68 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 8B D8 89 5C 24 ?? 83 FB ?? 74 ?? 85 DB 74 ?? 57 8D 44 24 ?? 
            89 7C 24 ?? 8B 3D ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 FF D7 33 F6 8D 44
        }

        $encrypt_files_p2 = {
            24 ?? 56 50 FF 74 24 ?? FF 74 24 ?? 53 FF D7 33 FF 68 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 83 C4 ?? FF 74 24 ?? 57 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 50 FF D6 
            FF 74 24 ?? 57 FF 15 ?? ?? ?? ?? 50 FF D6 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? E9 ?? ?? ?? 
            ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ?? 6A ?? FF 15 
            ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 F6 56 53 FF 15 ?? ?? ?? ?? 3D ?? 
            ?? ?? ?? 76 ?? 39 35 ?? ?? ?? ?? 75 ?? 56 53 FF 15 ?? ?? ?? ?? 56 8B F8 B8 ?? ?? ?? 
            ?? 56 50 53 2B F8 FF 15 ?? ?? ?? ?? 57 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 
            56 8D 8C 24 ?? ?? ?? ?? A3 ?? ?? ?? ?? 51 57 50 53 FF 15 ?? ?? ?? ?? 33 C0 50 50 50 
            53 FF 15 ?? ?? ?? ?? 33 F6 8D 84 24 ?? ?? ?? ?? 56 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            53 FF 15 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 
            15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B D8 6A ?? 89 5C 24 ?? FF 15 ?? 
            ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 89 44 24 ?? FF 15 ?? ?? ?? ?? 50 
            FF 15 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? BA 
            ?? ?? ?? ?? C1 E8 ?? 50 E8 ?? ?? ?? ?? 59 8D 94 24 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 85 C9 75 ?? 68 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 
            50 FF 15 
        }

        $find_files = {
            53 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8B 35 ?? ?? ?? ?? FF D6 83 C4 ?? 53 8D 85 ?? 
            ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 FF D6 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 8B F0 89 75 ?? 83 FE ?? 0F 84 ?? ?? ?? ?? 85 F6 0F 84 ?? ?? 
            ?? ?? 33 DB B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 
            66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 8B C3 EB ?? 1B C0 83 
            C8 ?? 85 C0 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 66 8B 10 66 3B 11 75 
            ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 8B 
            C3 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF B5 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 
            F6 85 ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 6A ?? 59 BE ?? ?? ?? ?? 8D BD ?? ?? ?? ?? F3 
            A5 6A ?? 59 BE ?? ?? ?? ?? 8D BD ?? ?? ?? ?? F3 A5 66 A5 6A ?? 59 BE ?? ?? ?? ?? 8D 
            BD ?? ?? ?? ?? F3 A5 66 A5 BE ?? ?? ?? ?? 8D BD ?? ?? ?? ?? A5 A5 A5 A5 50 E8 ?? ?? 
            ?? ?? 59 8B F0 8D 85 ?? ?? ?? ?? 50 56 E8 ?? ?? ?? ?? 59 59 85 C0 75 ?? 8D 85 ?? ?? 
            ?? ?? 50 56 E8 ?? ?? ?? ?? 59 59 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 56 E8 ?? ?? ?? ?? 
            59 59 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 56 E8 ?? ?? ?? ?? 59 59 85 C0 75 ?? FF 75 ?? 
            8B 55 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8B 75 ?? E9 ?? ?? ?? ?? FF 75 ?? E9 ?? 
            ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F8 66 39 1F 0F 84 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $find_files and 
            (
                all of ($encrypt_files_p*)
            ) and 
            (
                all of ($remote_connection_p*)
            )
        )
}