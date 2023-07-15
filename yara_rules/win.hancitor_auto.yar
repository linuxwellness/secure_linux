rule win_hancitor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.hancitor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hancitor"
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
        $sequence_0 = { 6a00 6a00 6824040000 6a00 }
            // n = 4, score = 1000
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6824040000           | push                0x424
            //   6a00                 | push                0

        $sequence_1 = { 6824040000 6a00 6a00 6a00 }
            // n = 4, score = 1000
            //   6824040000           | push                0x424
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_2 = { 6800010000 6a40 68???????? e8???????? }
            // n = 4, score = 900
            //   6800010000           | push                0x100
            //   6a40                 | push                0x40
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_3 = { 750d e8???????? 83c010 a3???????? }
            // n = 4, score = 800
            //   750d                 | jne                 0xf
            //   e8????????           |                     
            //   83c010               | add                 eax, 0x10
            //   a3????????           |                     

        $sequence_4 = { 6a20 68???????? 68???????? e8???????? 83c410 }
            // n = 5, score = 700
            //   6a20                 | push                0x20
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_5 = { 55 8bec 81ec58010000 6a44 }
            // n = 4, score = 700
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec58010000         | sub                 esp, 0x158
            //   6a44                 | push                0x44

        $sequence_6 = { 68???????? 8d85dcfaffff 50 ff15???????? }
            // n = 4, score = 700
            //   68????????           |                     
            //   8d85dcfaffff         | lea                 eax, [ebp - 0x524]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_7 = { 83ec0c 8b450c 53 56 57 8b483c 33f6 }
            // n = 7, score = 600
            //   83ec0c               | sub                 esp, 0xc
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b483c               | mov                 ecx, dword ptr [eax + 0x3c]
            //   33f6                 | xor                 esi, esi

        $sequence_8 = { 68???????? 8b4d08 51 ff15???????? 8d95f4fdffff }
            // n = 5, score = 600
            //   68????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d95f4fdffff         | lea                 edx, [ebp - 0x20c]

        $sequence_9 = { 83c102 51 e8???????? 83c404 8b550c }
            // n = 5, score = 600
            //   83c102               | add                 ecx, 2
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]

        $sequence_10 = { 8b483c 33f6 03c8 6a40 6800300000 }
            // n = 5, score = 600
            //   8b483c               | mov                 ecx, dword ptr [eax + 0x3c]
            //   33f6                 | xor                 esi, esi
            //   03c8                 | add                 ecx, eax
            //   6a40                 | push                0x40
            //   6800300000           | push                0x3000

        $sequence_11 = { 034228 8945f8 8b4df8 894df4 }
            // n = 4, score = 600
            //   034228               | add                 eax, dword ptr [edx + 0x28]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx

        $sequence_12 = { 8bec 83ec18 8b450c 8b4d0c 03483c 894dec 8b55ec }
            // n = 7, score = 600
            //   8bec                 | mov                 ebp, esp
            //   83ec18               | sub                 esp, 0x18
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   03483c               | add                 ecx, dword ptr [eax + 0x3c]
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]

        $sequence_13 = { 6a01 51 8b413c 8b440828 03c1 ffd0 }
            // n = 6, score = 600
            //   6a01                 | push                1
            //   51                   | push                ecx
            //   8b413c               | mov                 eax, dword ptr [ecx + 0x3c]
            //   8b440828             | mov                 eax, dword ptr [eax + ecx + 0x28]
            //   03c1                 | add                 eax, ecx
            //   ffd0                 | call                eax

        $sequence_14 = { ff7508 c605????????00 ff15???????? 33c0 }
            // n = 4, score = 600
            //   ff7508               | push                dword ptr [ebp + 8]
            //   c605????????00       |                     
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_15 = { 8b4514 8b4dfc 85c0 7402 8908 8b5518 }
            // n = 6, score = 600
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   85c0                 | test                eax, eax
            //   7402                 | je                  4
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]

        $sequence_16 = { 8bec 8b4d08 6a00 6a01 }
            // n = 4, score = 600
            //   8bec                 | mov                 ebp, esp
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   6a00                 | push                0
            //   6a01                 | push                1

        $sequence_17 = { 8034317a 41 3bc8 72f7 c6043000 40 5e }
            // n = 7, score = 600
            //   8034317a             | xor                 byte ptr [ecx + esi], 0x7a
            //   41                   | inc                 ecx
            //   3bc8                 | cmp                 ecx, eax
            //   72f7                 | jb                  0xfffffff9
            //   c6043000             | mov                 byte ptr [eax + esi], 0
            //   40                   | inc                 eax
            //   5e                   | pop                 esi

        $sequence_18 = { b808000000 6bc805 8b55e4 8d440a78 8945f0 8b4df0 8b11 }
            // n = 7, score = 600
            //   b808000000           | mov                 eax, 8
            //   6bc805               | imul                ecx, eax, 5
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   8d440a78             | lea                 eax, [edx + ecx + 0x78]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8b11                 | mov                 edx, dword ptr [ecx]

        $sequence_19 = { e9???????? b9382baa99 c745f464000000 8b45cc }
            // n = 4, score = 100
            //   e9????????           |                     
            //   b9382baa99           | mov                 ecx, 0x99aa2b38
            //   c745f464000000       | mov                 dword ptr [ebp - 0xc], 0x64
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]

        $sequence_20 = { 40 8945d0 8b45c0 83c008 8945c0 8b45b8 48 }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]
            //   83c008               | add                 eax, 8
            //   8945c0               | mov                 dword ptr [ebp - 0x40], eax
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]
            //   48                   | dec                 eax

        $sequence_21 = { 7440 c745880a000000 eb07 8b4588 40 894588 }
            // n = 6, score = 100
            //   7440                 | je                  0x42
            //   c745880a000000       | mov                 dword ptr [ebp - 0x78], 0xa
            //   eb07                 | jmp                 9
            //   8b4588               | mov                 eax, dword ptr [ebp - 0x78]
            //   40                   | inc                 eax
            //   894588               | mov                 dword ptr [ebp - 0x78], eax

        $sequence_22 = { c645fc65 c645fd00 c745f8dc030000 8365b800 eb07 8b45b8 }
            // n = 6, score = 100
            //   c645fc65             | mov                 byte ptr [ebp - 4], 0x65
            //   c645fd00             | mov                 byte ptr [ebp - 3], 0
            //   c745f8dc030000       | mov                 dword ptr [ebp - 8], 0x3dc
            //   8365b800             | and                 dword ptr [ebp - 0x48], 0
            //   eb07                 | jmp                 9
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]

        $sequence_23 = { 83c05b a3???????? a1???????? 0345cc a3???????? 817df8b07d0900 0f8ced000000 }
            // n = 7, score = 100
            //   83c05b               | add                 eax, 0x5b
            //   a3????????           |                     
            //   a1????????           |                     
            //   0345cc               | add                 eax, dword ptr [ebp - 0x34]
            //   a3????????           |                     
            //   817df8b07d0900       | cmp                 dword ptr [ebp - 8], 0x97db0
            //   0f8ced000000         | jl                  0xf3

        $sequence_24 = { 894588 817d886c972d01 7d27 8b45e4 0345c0 8945e4 }
            // n = 6, score = 100
            //   894588               | mov                 dword ptr [ebp - 0x78], eax
            //   817d886c972d01       | cmp                 dword ptr [ebp - 0x78], 0x12d976c
            //   7d27                 | jge                 0x29
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   0345c0               | add                 eax, dword ptr [ebp - 0x40]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_25 = { 8365d400 c745d0049d4000 a1???????? 8945d8 c705????????053f0f00 }
            // n = 5, score = 100
            //   8365d400             | and                 dword ptr [ebp - 0x2c], 0
            //   c745d0049d4000       | mov                 dword ptr [ebp - 0x30], 0x409d04
            //   a1????????           |                     
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   c705????????053f0f00     |     

        $sequence_26 = { a1???????? 83c044 a3???????? 8b45a0 05c8d45566 }
            // n = 5, score = 100
            //   a1????????           |                     
            //   83c044               | add                 eax, 0x44
            //   a3????????           |                     
            //   8b45a0               | mov                 eax, dword ptr [ebp - 0x60]
            //   05c8d45566           | add                 eax, 0x6655d4c8

    condition:
        7 of them and filesize < 106496
}