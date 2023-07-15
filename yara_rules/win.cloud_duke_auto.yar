rule win_cloud_duke_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.cloud_duke."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cloud_duke"
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
        $sequence_0 = { 57 ff15???????? 85c0 750b ff15???????? 83f87a 7564 }
            // n = 7, score = 800
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   750b                 | jne                 0xd
            //   ff15????????         |                     
            //   83f87a               | cmp                 eax, 0x7a
            //   7564                 | jne                 0x66

        $sequence_1 = { ff74241c 8d8c2424010000 e8???????? 8d842440010000 ba???????? 50 8d8c2494000000 }
            // n = 7, score = 800
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   8d8c2424010000       | lea                 ecx, [esp + 0x124]
            //   e8????????           |                     
            //   8d842440010000       | lea                 eax, [esp + 0x140]
            //   ba????????           |                     
            //   50                   | push                eax
            //   8d8c2494000000       | lea                 ecx, [esp + 0x94]

        $sequence_2 = { 8b8a88e8ffff 33c8 e8???????? 83c008 8b4af8 33c8 e8???????? }
            // n = 7, score = 800
            //   8b8a88e8ffff         | mov                 ecx, dword ptr [edx - 0x1778]
            //   33c8                 | xor                 ecx, eax
            //   e8????????           |                     
            //   83c008               | add                 eax, 8
            //   8b4af8               | mov                 ecx, dword ptr [edx - 8]
            //   33c8                 | xor                 ecx, eax
            //   e8????????           |                     

        $sequence_3 = { 2b4c2430 f7e9 c1fa02 8bc2 c1e81f 03c2 898424b8000000 }
            // n = 7, score = 800
            //   2b4c2430             | sub                 ecx, dword ptr [esp + 0x30]
            //   f7e9                 | imul                ecx
            //   c1fa02               | sar                 edx, 2
            //   8bc2                 | mov                 eax, edx
            //   c1e81f               | shr                 eax, 0x1f
            //   03c2                 | add                 eax, edx
            //   898424b8000000       | mov                 dword ptr [esp + 0xb8], eax

        $sequence_4 = { 0fbe44241b 83c0d0 83f803 0f870f070000 }
            // n = 4, score = 800
            //   0fbe44241b           | movsx               eax, byte ptr [esp + 0x1b]
            //   83c0d0               | add                 eax, -0x30
            //   83f803               | cmp                 eax, 3
            //   0f870f070000         | ja                  0x715

        $sequence_5 = { e8???????? 83c40c c78424b800000000000000 8d8424b8000000 50 }
            // n = 5, score = 800
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c78424b800000000000000     | mov    dword ptr [esp + 0xb8], 0
            //   8d8424b8000000       | lea                 eax, [esp + 0xb8]
            //   50                   | push                eax

        $sequence_6 = { 55 8bec 8b4508 81c1c8000000 3bc8 740a }
            // n = 6, score = 800
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   81c1c8000000         | add                 ecx, 0xc8
            //   3bc8                 | cmp                 ecx, eax
            //   740a                 | je                  0xc

        $sequence_7 = { 50 8d4c247c e8???????? 83c404 6aff 6a00 50 }
            // n = 7, score = 800
            //   50                   | push                eax
            //   8d4c247c             | lea                 ecx, [esp + 0x7c]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   6aff                 | push                -1
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_8 = { f3a5 8bca 83e103 f3a4 8b85e8fbffff 8bb5e0fbffff }
            // n = 6, score = 800
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bca                 | mov                 ecx, edx
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b85e8fbffff         | mov                 eax, dword ptr [ebp - 0x418]
            //   8bb5e0fbffff         | mov                 esi, dword ptr [ebp - 0x420]

        $sequence_9 = { c7868c00000000000000 7711 c786f800000003000000 32c0 e9???????? 33c9 c78424d000000007000000 }
            // n = 7, score = 800
            //   c7868c00000000000000     | mov    dword ptr [esi + 0x8c], 0
            //   7711                 | ja                  0x13
            //   c786f800000003000000     | mov    dword ptr [esi + 0xf8], 3
            //   32c0                 | xor                 al, al
            //   e9????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   c78424d000000007000000     | mov    dword ptr [esp + 0xd0], 7

    condition:
        7 of them and filesize < 368640
}