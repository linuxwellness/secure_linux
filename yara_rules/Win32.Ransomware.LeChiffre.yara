rule Win32_Ransomware_LeChiffre : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "LECHIFFRE"
        description         = "Yara rule that detects LeChiffre ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "LeChiffre"
        tc_detection_factor = 5

    strings:

        $remote_connection_1 = {
            55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 89 45 ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 
            30 64 89 20 8B 45 ?? 33 D2 E8 ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 
            ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 45 ?? 
            E8 ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 
            ?? 8B 08 FF 51 ?? 8B 45 ?? 8B 10 FF 52 ?? 8B F0 4E 85 F6 7C ?? 46 33 DB 8D 4D ?? 8B 
            D3 8B 45 ?? 8B 38 FF 57 ?? 8B 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 7E ?? 8D 45 
            ?? 50 8D 4D ?? 8B D3 8B 45 ?? 8B 38 FF 57 ?? 8B 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            83 E8 ?? 50 8D 4D ?? 8B D3 8B 45 ?? 8B 38 FF 57 ?? 8B 45 ?? BA ?? ?? ?? ?? 59 E8 ?? 
            ?? ?? ?? 43 4E 75 ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 
            8B 45 ?? E8 ?? ?? ?? ?? C3 
        }

        $remote_connection_2 = {
            55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 33 
            C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 ?? 8B 80 ?? ?? ?? ?? 66 BE ?? ?? E8 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 8D 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 8D 55 ?? E8 
            ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8B 45 ?? 8D 55 ?? E8 ?? ?? ?? ?? FF 75 ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B 55 ?? 8D 45 ?? E8 ?? ?? ?? ?? 8B 4D ?? BA ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? 
            ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? C3 
        }

        $remote_connection_3 = {
            E8 ?? ?? ?? ?? 8B 45 ?? 8B 80 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? B2 ?? A1 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 E8 ?? ?? 
            ?? ?? DD 5D ?? 9B FF 75 ?? FF 75 ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? 
            ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8B 45 ?? 8D 55 ?? E8 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? 8D 45 ?? 
            8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 8D 55 ?? E8 ?? ?? ?? ?? FF 
            75 ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 8D 45 ?? E8 ?? ?? ?? ?? 8B 4D 
            ?? BA ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 
            45 ?? E8 ?? ?? ?? ?? C3 
        }

        $encrypt_files_1 = {
            E8 ?? ?? ?? ?? 8D 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 
            8B 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 55 ?? 8B 45 ?? E8 
            ?? ?? ?? ?? 8B 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 55 ?? 
            8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? 
            ?? 83 7B ?? ?? 0F 84 ?? ?? ?? ?? 8B 13 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 
            03 E8 ?? ?? ?? ?? 84 C0 75 ?? 8B 03 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 74 ?? FF 86 ?? ?? 
            ?? ?? B2 ?? 8B 86 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 ?? 8B 03 E8 ?? ?? ?? ?? FF 75 ?? 
            68 ?? ?? ?? ?? 8B 43 ?? C1 E8 ?? 33 D2 52 50 8D 45 ?? E8 ?? ?? ?? ?? FF 75 ?? 68 ?? 
            ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 86 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B 03 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? C3 
        }

        $encrypt_files_2 = {
            E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? 8B 12 8B 92 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 
            45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 8B 40 ?? 8B 55 ?? E8 ?? ?? ?? ?? 3D ?? 
            ?? ?? ?? 0F 85 ?? ?? ?? ?? 8B 45 ?? FF 70 ?? 68 ?? ?? ?? ?? FF 75 ?? 8D 85 ?? ?? ?? 
            ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 8B 45 ?? 8B 40 
            ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 45 ?? 50 68 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? 
            ?? 8D 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? 
            ?? ?? 8B 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 
            FF 30 64 89 20 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 00 
            8B 90 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 
            C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            C3 E9 ?? ?? ?? ?? EB ?? 8D 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 
            85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? B9 ?? ?? ?? 
            ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 
            55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            A1 ?? ?? ?? ?? 8B 00 8B 90 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 8B 45 ?? 50 68 ?? ?? ?? ?? 8B 45 ?? E8 
            ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 ?? 50 68 ?? ?? ?? ?? 8B 45 
            ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 
            85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            C3 E9 ?? ?? ?? ?? EB ?? 8B E5 5D C3 
        }

        $find_files = {
            E8 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8B 55 ?? 8B C3 E8 ?? ?? ?? ?? 
            84 C0 0F 85 ?? ?? ?? ?? 33 C0 89 43 ?? 8B 43 ?? E8 ?? ?? ?? ?? 8B F0 85 F6 7C ?? 46 
            33 FF 8B 43 ?? C7 04 B8 ?? ?? ?? ?? 47 4E 75 ?? 8B 43 ?? 8B 40 ?? E8 ?? ?? ?? ?? 8B 
            F0 85 F6 7C ?? 46 33 FF 8B 43 ?? 8B 40 ?? 8B 14 B8 8D 8D ?? ?? ?? ?? 8B 45 ?? E8 ?? 
            ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8B 43 ?? 8B 53 ?? 89 14 B8 47 4E 75 
            ?? 8B 73 ?? 4E 85 F6 7C ?? 46 33 FF 80 7B ?? ?? 0F 85 ?? ?? ?? ?? 8D 04 BF 8B 53 ?? 
            8D 04 C2 89 43 ?? 89 45 ?? 8D 8D ?? ?? ?? ?? 8B 45 ?? 8B 10 8B 45 ?? E8 ?? ?? ?? ?? 
            8B 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8B 
            45 ?? 33 D2 E8 ?? ?? ?? ?? 47 4E 75 ?? 8B 43 ?? 8B 40 ?? 80 78 ?? ?? 0F 84 ?? ?? ?? 
            ?? 80 7B ?? ?? 0F 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? BA ?? ?? ?? 
            ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 89 45 
            ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 F6 85 ?? 
            ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 74 ?? 8D 85 ?? ?? ?? ?? 
            8D 95 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 74 ?? 8D 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8B 95 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B C3 
            E8 ?? ?? ?? ?? 80 7B ?? ?? 75 ?? 8D 85 ?? ?? ?? ?? 50 8B 45 ?? 50 E8 ?? ?? ?? ?? 85 
            C0 0F 85 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? 
            ?? C3 E9 ?? ?? ?? ?? EB ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 5F 5E 5B 8B E5 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and $find_files and $encrypt_files_1 and $encrypt_files_2 and $remote_connection_1 and $remote_connection_2 and $remote_connection_3
}