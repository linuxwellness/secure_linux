rule win_woodyrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.woodyrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.woodyrat"
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
        $sequence_0 = { 8b45e0 895804 eb02 8bc1 8b4df4 64890d00000000 59 }
            // n = 7, score = 100
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   895804               | mov                 dword ptr [eax + 4], ebx
            //   eb02                 | jmp                 4
            //   8bc1                 | mov                 eax, ecx
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx

        $sequence_1 = { 8b45b4 8b4db8 8985b0feffff 898da4feffff 3bc1 0f8404030000 0f1f440000 }
            // n = 7, score = 100
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   8b4db8               | mov                 ecx, dword ptr [ebp - 0x48]
            //   8985b0feffff         | mov                 dword ptr [ebp - 0x150], eax
            //   898da4feffff         | mov                 dword ptr [ebp - 0x15c], ecx
            //   3bc1                 | cmp                 eax, ecx
            //   0f8404030000         | je                  0x30a
            //   0f1f440000           | nop                 dword ptr [eax + eax]

        $sequence_2 = { 8d4601 50 8d4dcc e8???????? 83bd7cffffff08 8bc8 8b4598 }
            // n = 7, score = 100
            //   8d4601               | lea                 eax, [esi + 1]
            //   50                   | push                eax
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   e8????????           |                     
            //   83bd7cffffff08       | cmp                 dword ptr [ebp - 0x84], 8
            //   8bc8                 | mov                 ecx, eax
            //   8b4598               | mov                 eax, dword ptr [ebp - 0x68]

        $sequence_3 = { 83fe08 8d45cc 0f43c7 83fa11 752c b9???????? }
            // n = 6, score = 100
            //   83fe08               | cmp                 esi, 8
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   0f43c7               | cmovae              eax, edi
            //   83fa11               | cmp                 edx, 0x11
            //   752c                 | jne                 0x2e
            //   b9????????           |                     

        $sequence_4 = { 6a01 ff500c 83c604 3bf3 75ec 8b4724 85c0 }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   ff500c               | call                dword ptr [eax + 0xc]
            //   83c604               | add                 esi, 4
            //   3bf3                 | cmp                 esi, ebx
            //   75ec                 | jne                 0xffffffee
            //   8b4724               | mov                 eax, dword ptr [edi + 0x24]
            //   85c0                 | test                eax, eax

        $sequence_5 = { 894d10 e8???????? 83c430 33f6 eb20 837de810 8d45d4 }
            // n = 7, score = 100
            //   894d10               | mov                 dword ptr [ebp + 0x10], ecx
            //   e8????????           |                     
            //   83c430               | add                 esp, 0x30
            //   33f6                 | xor                 esi, esi
            //   eb20                 | jmp                 0x22
            //   837de810             | cmp                 dword ptr [ebp - 0x18], 0x10
            //   8d45d4               | lea                 eax, [ebp - 0x2c]

        $sequence_6 = { 0f57c0 89b5ecf9ffff b8983a0000 660fd685e4f9ffff 898534f9ffff 89b5e4f9ffff 89b5e8f9ffff }
            // n = 7, score = 100
            //   0f57c0               | xorps               xmm0, xmm0
            //   89b5ecf9ffff         | mov                 dword ptr [ebp - 0x614], esi
            //   b8983a0000           | mov                 eax, 0x3a98
            //   660fd685e4f9ffff     | movq                qword ptr [ebp - 0x61c], xmm0
            //   898534f9ffff         | mov                 dword ptr [ebp - 0x6cc], eax
            //   89b5e4f9ffff         | mov                 dword ptr [ebp - 0x61c], esi
            //   89b5e8f9ffff         | mov                 dword ptr [ebp - 0x618], esi

        $sequence_7 = { c745c800000000 ff15???????? 33c0 c7461000000000 c7461407000000 668906 }
            // n = 6, score = 100
            //   c745c800000000       | mov                 dword ptr [ebp - 0x38], 0
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   c7461407000000       | mov                 dword ptr [esi + 0x14], 7
            //   668906               | mov                 word ptr [esi], ax

        $sequence_8 = { 83c0fc 83f81f 0f875b080000 52 51 e8???????? 83c408 }
            // n = 7, score = 100
            //   83c0fc               | add                 eax, -4
            //   83f81f               | cmp                 eax, 0x1f
            //   0f875b080000         | ja                  0x861
            //   52                   | push                edx
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_9 = { e8???????? 83c404 83bd04ffffff00 c745fc09000000 0f8574010000 6a10 6a00 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   83bd04ffffff00       | cmp                 dword ptr [ebp - 0xfc], 0
            //   c745fc09000000       | mov                 dword ptr [ebp - 4], 9
            //   0f8574010000         | jne                 0x17a
            //   6a10                 | push                0x10
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 785408
}