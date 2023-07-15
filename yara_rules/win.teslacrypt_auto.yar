rule win_teslacrypt_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.teslacrypt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.teslacrypt"
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
        $sequence_0 = { 338598000000 8985b8000000 33859c000000 8985bc000000 }
            // n = 4, score = 900
            //   338598000000         | xor                 eax, dword ptr [ebp + 0x98]
            //   8985b8000000         | mov                 dword ptr [ebp + 0xb8], eax
            //   33859c000000         | xor                 eax, dword ptr [ebp + 0x9c]
            //   8985bc000000         | mov                 dword ptr [ebp + 0xbc], eax

        $sequence_1 = { 338594000000 8985b4000000 338598000000 8985b8000000 }
            // n = 4, score = 900
            //   338594000000         | xor                 eax, dword ptr [ebp + 0x94]
            //   8985b4000000         | mov                 dword ptr [ebp + 0xb4], eax
            //   338598000000         | xor                 eax, dword ptr [ebp + 0x98]
            //   8985b8000000         | mov                 dword ptr [ebp + 0xb8], eax

        $sequence_2 = { 33550c 81ffa0000000 0f8452030000 81ffc0000000 0f84ac010000 81ffe0000000 }
            // n = 6, score = 900
            //   33550c               | xor                 edx, dword ptr [ebp + 0xc]
            //   81ffa0000000         | cmp                 edi, 0xa0
            //   0f8452030000         | je                  0x358
            //   81ffc0000000         | cmp                 edi, 0xc0
            //   0f84ac010000         | je                  0x1b2
            //   81ffe0000000         | cmp                 edi, 0xe0

        $sequence_3 = { 0f84ac010000 81ffe0000000 740a b8ffffffff e9???????? 83c510 8b7508 }
            // n = 7, score = 900
            //   0f84ac010000         | je                  0x1b2
            //   81ffe0000000         | cmp                 edi, 0xe0
            //   740a                 | je                  0xc
            //   b8ffffffff           | mov                 eax, 0xffffffff
            //   e9????????           |                     
            //   83c510               | add                 ebp, 0x10
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_4 = { 31f9 898d88000000 31ca 89958c000000 89d0 51 52 }
            // n = 7, score = 900
            //   31f9                 | xor                 ecx, edi
            //   898d88000000         | mov                 dword ptr [ebp + 0x88], ecx
            //   31ca                 | xor                 edx, ecx
            //   89958c000000         | mov                 dword ptr [ebp + 0x8c], edx
            //   89d0                 | mov                 eax, edx
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_5 = { 0f8456030000 81ffc0000000 0f84ae010000 81ffe0000000 740a b8ffffffff }
            // n = 6, score = 900
            //   0f8456030000         | je                  0x35c
            //   81ffc0000000         | cmp                 edi, 0xc0
            //   0f84ae010000         | je                  0x1b4
            //   81ffe0000000         | cmp                 edi, 0xe0
            //   740a                 | je                  0xc
            //   b8ffffffff           | mov                 eax, 0xffffffff

        $sequence_6 = { 33550c 81ffa0000000 0f8456030000 81ffc0000000 }
            // n = 4, score = 900
            //   33550c               | xor                 edx, dword ptr [ebp + 0xc]
            //   81ffa0000000         | cmp                 edi, 0xa0
            //   0f8456030000         | je                  0x35c
            //   81ffc0000000         | cmp                 edi, 0xc0

        $sequence_7 = { 33859c000000 8985bc000000 51 52 }
            // n = 4, score = 900
            //   33859c000000         | xor                 eax, dword ptr [ebp + 0x9c]
            //   8985bc000000         | mov                 dword ptr [ebp + 0xbc], eax
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_8 = { 8b91a4000000 83fa00 89542464 89442468 0f84d3010000 }
            // n = 5, score = 100
            //   8b91a4000000         | mov                 edx, dword ptr [ecx + 0xa4]
            //   83fa00               | cmp                 edx, 0
            //   89542464             | mov                 dword ptr [esp + 0x64], edx
            //   89442468             | mov                 dword ptr [esp + 0x68], eax
            //   0f84d3010000         | je                  0x1d9

        $sequence_9 = { 890424 e8???????? 8b4c240c 034850 8b442410 39c8 0f92c2 }
            // n = 7, score = 100
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   034850               | add                 ecx, dword ptr [eax + 0x50]
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   39c8                 | cmp                 eax, ecx
            //   0f92c2               | setb                dl

        $sequence_10 = { 31db 85ff 89442420 8954241c 894c2418 897c2414 }
            // n = 6, score = 100
            //   31db                 | xor                 ebx, ebx
            //   85ff                 | test                edi, edi
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   8954241c             | mov                 dword ptr [esp + 0x1c], edx
            //   894c2418             | mov                 dword ptr [esp + 0x18], ecx
            //   897c2414             | mov                 dword ptr [esp + 0x14], edi

        $sequence_11 = { 01d6 8b7c2464 8b54170c 83fa00 89542454 89742450 }
            // n = 6, score = 100
            //   01d6                 | add                 esi, edx
            //   8b7c2464             | mov                 edi, dword ptr [esp + 0x64]
            //   8b54170c             | mov                 edx, dword ptr [edi + edx + 0xc]
            //   83fa00               | cmp                 edx, 0
            //   89542454             | mov                 dword ptr [esp + 0x54], edx
            //   89742450             | mov                 dword ptr [esp + 0x50], esi

        $sequence_12 = { 83ec34 8b442448 8b4c2444 890424 89442430 }
            // n = 5, score = 100
            //   83ec34               | sub                 esp, 0x34
            //   8b442448             | mov                 eax, dword ptr [esp + 0x48]
            //   8b4c2444             | mov                 ecx, dword ptr [esp + 0x44]
            //   890424               | mov                 dword ptr [esp], eax
            //   89442430             | mov                 dword ptr [esp + 0x30], eax

        $sequence_13 = { 884c2423 886c2422 8974241c 8b44241c 668b4824 8b5028 89c6 }
            // n = 7, score = 100
            //   884c2423             | mov                 byte ptr [esp + 0x23], cl
            //   886c2422             | mov                 byte ptr [esp + 0x22], ch
            //   8974241c             | mov                 dword ptr [esp + 0x1c], esi
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   668b4824             | mov                 cx, word ptr [eax + 0x24]
            //   8b5028               | mov                 edx, dword ptr [eax + 0x28]
            //   89c6                 | mov                 esi, eax

        $sequence_14 = { c78424b800000000000000 8b504c 8b7020 8b7848 }
            // n = 4, score = 100
            //   c78424b800000000000000     | mov    dword ptr [esp + 0xb8], 0
            //   8b504c               | mov                 edx, dword ptr [eax + 0x4c]
            //   8b7020               | mov                 esi, dword ptr [eax + 0x20]
            //   8b7848               | mov                 edi, dword ptr [eax + 0x48]

        $sequence_15 = { 0f8488000000 eb90 31c0 668b4c2416 66c1e901 }
            // n = 5, score = 100
            //   0f8488000000         | je                  0x8e
            //   eb90                 | jmp                 0xffffff92
            //   31c0                 | xor                 eax, eax
            //   668b4c2416           | mov                 cx, word ptr [esp + 0x16]
            //   66c1e901             | shr                 cx, 1

    condition:
        7 of them and filesize < 1187840
}