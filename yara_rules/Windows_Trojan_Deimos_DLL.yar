rule Windows_Trojan_Deimos_DLL {
    meta:
        author = "Elastic Security"
        creation_date = "2021-09-18"
        last_modified = "2021-09-18"
        os = "Windows"
        arch = "x86"
        category_type = "Trojan"
        family = "Deimos"
        threat_name = "Windows.Trojan.Deimos"
        description = "Detects the presence of the Deimos trojan DLL file."
        reference = "https://www.elastic.co/security-labs/going-coast-to-coast-climbing-the-pyramid-with-the-deimos-implant"
        reference_sample = "2c1941847f660a99bbc6de16b00e563f70d900f9dbc40c6734871993961d3d3e"

    strings:
        $a1 = "\\APPDATA\\ROAMING" wide fullword
        $a2 = "{\"action\":\"ping\",\"" wide fullword
        $a3 = "Deimos" ascii fullword
        $b1 = { 00 57 00 58 00 59 00 5A 00 5F 00 00 17 75 00 73 00 65 00 72 00 }
        $b2 = { 0C 08 16 1F 68 9D 08 17 1F 77 9D 08 18 1F 69 9D 08 19 1F 64 9D }
    condition:
        all of ($a*) or 1 of ($b*)
}
