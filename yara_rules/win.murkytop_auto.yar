rule win_murkytop_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.murkytop."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.murkytop"
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
        $sequence_0 = { 8b4e08 51 e8???????? 83c40c 50 68???????? }
            // n = 6, score = 100
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_1 = { 6840040000 ff15???????? 3bc3 7541 ff15???????? 53 53 }
            // n = 7, score = 100
            //   6840040000           | push                0x440
            //   ff15????????         |                     
            //   3bc3                 | cmp                 eax, ebx
            //   7541                 | jne                 0x43
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   53                   | push                ebx

        $sequence_2 = { 83c408 85c0 7513 68???????? e8???????? }
            // n = 5, score = 100
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7513                 | jne                 0x15
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_3 = { 7620 8b4df8 8b14b9 52 }
            // n = 4, score = 100
            //   7620                 | jbe                 0x22
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8b14b9               | mov                 edx, dword ptr [ecx + edi*4]
            //   52                   | push                edx

        $sequence_4 = { 7445 3c70 7426 3c50 7422 3c6e 7415 }
            // n = 7, score = 100
            //   7445                 | je                  0x47
            //   3c70                 | cmp                 al, 0x70
            //   7426                 | je                  0x28
            //   3c50                 | cmp                 al, 0x50
            //   7422                 | je                  0x24
            //   3c6e                 | cmp                 al, 0x6e
            //   7415                 | je                  0x17

        $sequence_5 = { 6a00 ff15???????? 85c0 752b ff15???????? 8b0f 51 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   752b                 | jne                 0x2d
            //   ff15????????         |                     
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   51                   | push                ecx

        $sequence_6 = { 7cd3 33c0 40 5f 5e c3 8324f5d0c4410000 }
            // n = 7, score = 100
            //   7cd3                 | jl                  0xffffffd5
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8324f5d0c4410000     | and                 dword ptr [esi*8 + 0x41c4d0], 0

        $sequence_7 = { 52 56 6a00 6a00 68???????? 8b45c8 50 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   56                   | push                esi
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   50                   | push                eax

        $sequence_8 = { 8975f4 8975e0 ff15???????? 3bc6 7407 3dea000000 }
            // n = 6, score = 100
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   ff15????????         |                     
            //   3bc6                 | cmp                 eax, esi
            //   7407                 | je                  9
            //   3dea000000           | cmp                 eax, 0xea

        $sequence_9 = { 3dfeffff3f 0f8736030000 8bcf 2bce 40 c1f902 3bc1 }
            // n = 7, score = 100
            //   3dfeffff3f           | cmp                 eax, 0x3ffffffe
            //   0f8736030000         | ja                  0x33c
            //   8bcf                 | mov                 ecx, edi
            //   2bce                 | sub                 ecx, esi
            //   40                   | inc                 eax
            //   c1f902               | sar                 ecx, 2
            //   3bc1                 | cmp                 eax, ecx

    condition:
        7 of them and filesize < 294912
}