rule win_pcshare_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.pcshare."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pcshare"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 68???????? 51 e8???????? 8dbc2474010000 83c9ff 33c0 83c410 }
            // n = 7, score = 100
            //   68????????           |                     
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8dbc2474010000       | lea                 edi, [esp + 0x174]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   83c410               | add                 esp, 0x10

        $sequence_1 = { 52 50 68???????? 56 e8???????? 83c410 8d4c2454 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   50                   | push                eax
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8d4c2454             | lea                 ecx, [esp + 0x54]

        $sequence_2 = { e8???????? 85c0 59 743e 8305????????20 8d0c9da0720610 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   59                   | pop                 ecx
            //   743e                 | je                  0x40
            //   8305????????20       |                     
            //   8d0c9da0720610       | lea                 ecx, [ebx*4 + 0x100672a0]

        $sequence_3 = { 6685db 744a 0fb6c3 f680e184061004 741a 8a4601 }
            // n = 6, score = 100
            //   6685db               | test                bx, bx
            //   744a                 | je                  0x4c
            //   0fb6c3               | movzx               eax, bl
            //   f680e184061004       | test                byte ptr [eax + 0x100684e1], 4
            //   741a                 | je                  0x1c
            //   8a4601               | mov                 al, byte ptr [esi + 1]

        $sequence_4 = { 8b8c24cc010000 c744241440000000 2b790c 897c2420 8b5c2420 8b9424cc010000 8b8c24d0010000 }
            // n = 7, score = 100
            //   8b8c24cc010000       | mov                 ecx, dword ptr [esp + 0x1cc]
            //   c744241440000000     | mov                 dword ptr [esp + 0x14], 0x40
            //   2b790c               | sub                 edi, dword ptr [ecx + 0xc]
            //   897c2420             | mov                 dword ptr [esp + 0x20], edi
            //   8b5c2420             | mov                 ebx, dword ptr [esp + 0x20]
            //   8b9424cc010000       | mov                 edx, dword ptr [esp + 0x1cc]
            //   8b8c24d0010000       | mov                 ecx, dword ptr [esp + 0x1d0]

        $sequence_5 = { c1e705 03cf 8bf8 c1ff10 25ffff0000 }
            // n = 5, score = 100
            //   c1e705               | shl                 edi, 5
            //   03cf                 | add                 ecx, edi
            //   8bf8                 | mov                 edi, eax
            //   c1ff10               | sar                 edi, 0x10
            //   25ffff0000           | and                 eax, 0xffff

        $sequence_6 = { 8d0440 8d04c598500610 50 ff15???????? c20400 6a30 }
            // n = 6, score = 100
            //   8d0440               | lea                 eax, [eax + eax*2]
            //   8d04c598500610       | lea                 eax, [eax*8 + 0x10065098]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   c20400               | ret                 4
            //   6a30                 | push                0x30

        $sequence_7 = { 8bb424d0010000 c7442414ffffffff 8b5604 52 50 8d442440 68???????? }
            // n = 7, score = 100
            //   8bb424d0010000       | mov                 esi, dword ptr [esp + 0x1d0]
            //   c7442414ffffffff     | mov                 dword ptr [esp + 0x14], 0xffffffff
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   52                   | push                edx
            //   50                   | push                eax
            //   8d442440             | lea                 eax, [esp + 0x40]
            //   68????????           |                     

        $sequence_8 = { 8d4c2801 894c2414 eb6b 56 e8???????? 8b54242c 8bd8 }
            // n = 7, score = 100
            //   8d4c2801             | lea                 ecx, [eax + ebp + 1]
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx
            //   eb6b                 | jmp                 0x6d
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]
            //   8bd8                 | mov                 ebx, eax

        $sequence_9 = { 3bc6 7423 837f3401 751d 8b5748 8bc8 }
            // n = 6, score = 100
            //   3bc6                 | cmp                 eax, esi
            //   7423                 | je                  0x25
            //   837f3401             | cmp                 dword ptr [edi + 0x34], 1
            //   751d                 | jne                 0x1f
            //   8b5748               | mov                 edx, dword ptr [edi + 0x48]
            //   8bc8                 | mov                 ecx, eax

    condition:
        7 of them and filesize < 893708
}