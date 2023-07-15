rule win_fickerstealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.fickerstealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fickerstealer"
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
        $sequence_0 = { b120 84c8 b800000000 8b4dec 0f45da 0f45d0 }
            // n = 6, score = 200
            //   b120                 | mov                 cl, 0x20
            //   84c8                 | test                al, cl
            //   b800000000           | mov                 eax, 0
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   0f45da               | cmovne              ebx, edx
            //   0f45d0               | cmovne              edx, eax

        $sequence_1 = { 8d942424040000 8dbc24a0010000 8b72f8 89f9 e8???????? 8b3f 83ff02 }
            // n = 7, score = 200
            //   8d942424040000       | lea                 edx, [esp + 0x424]
            //   8dbc24a0010000       | lea                 edi, [esp + 0x1a0]
            //   8b72f8               | mov                 esi, dword ptr [edx - 8]
            //   89f9                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b3f                 | mov                 edi, dword ptr [edi]
            //   83ff02               | cmp                 edi, 2

        $sequence_2 = { f20f10842448010000 f20f108c2450010000 8d8c24e4000000 89e2 f20f114c2408 f20f110424 e8???????? }
            // n = 7, score = 200
            //   f20f10842448010000     | movsd    xmm0, qword ptr [esp + 0x148]
            //   f20f108c2450010000     | movsd    xmm1, qword ptr [esp + 0x150]
            //   8d8c24e4000000       | lea                 ecx, [esp + 0xe4]
            //   89e2                 | mov                 edx, esp
            //   f20f114c2408         | movsd               qword ptr [esp + 8], xmm1
            //   f20f110424           | movsd               qword ptr [esp], xmm0
            //   e8????????           |                     

        $sequence_3 = { 89f3 8d7c5202 eb78 89c2 89f8 8b7dec 84db }
            // n = 7, score = 200
            //   89f3                 | mov                 ebx, esi
            //   8d7c5202             | lea                 edi, [edx + edx*2 + 2]
            //   eb78                 | jmp                 0x7a
            //   89c2                 | mov                 edx, eax
            //   89f8                 | mov                 eax, edi
            //   8b7dec               | mov                 edi, dword ptr [ebp - 0x14]
            //   84db                 | test                bl, bl

        $sequence_4 = { f20f1045d8 f20f104de0 8817 884f01 c6470401 885f05 894708 }
            // n = 7, score = 200
            //   f20f1045d8           | movsd               xmm0, qword ptr [ebp - 0x28]
            //   f20f104de0           | movsd               xmm1, qword ptr [ebp - 0x20]
            //   8817                 | mov                 byte ptr [edi], dl
            //   884f01               | mov                 byte ptr [edi + 1], cl
            //   c6470401             | mov                 byte ptr [edi + 4], 1
            //   885f05               | mov                 byte ptr [edi + 5], bl
            //   894708               | mov                 dword ptr [edi + 8], eax

        $sequence_5 = { e8???????? 8b4dd8 89c7 e8???????? 0fb74de6 0fb755ec 66890e }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   89c7                 | mov                 edi, eax
            //   e8????????           |                     
            //   0fb74de6             | movzx               ecx, word ptr [ebp - 0x1a]
            //   0fb755ec             | movzx               edx, word ptr [ebp - 0x14]
            //   66890e               | mov                 word ptr [esi], cx

        $sequence_6 = { ff7508 e8???????? 58 8b5708 8b4704 833f01 7511 }
            // n = 7, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   58                   | pop                 eax
            //   8b5708               | mov                 edx, dword ptr [edi + 8]
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   833f01               | cmp                 dword ptr [edi], 1
            //   7511                 | jne                 0x13

        $sequence_7 = { 83e007 09fb 81e1ffff7f00 09cb 83f805 7203 43 }
            // n = 7, score = 200
            //   83e007               | and                 eax, 7
            //   09fb                 | or                  ebx, edi
            //   81e1ffff7f00         | and                 ecx, 0x7fffff
            //   09cb                 | or                  ebx, ecx
            //   83f805               | cmp                 eax, 5
            //   7203                 | jb                  5
            //   43                   | inc                 ebx

        $sequence_8 = { 8d4670 898424ac010000 6a1c 59 8dbc2430010000 e9???????? 83bc24a801000001 }
            // n = 7, score = 200
            //   8d4670               | lea                 eax, [esi + 0x70]
            //   898424ac010000       | mov                 dword ptr [esp + 0x1ac], eax
            //   6a1c                 | push                0x1c
            //   59                   | pop                 ecx
            //   8dbc2430010000       | lea                 edi, [esp + 0x130]
            //   e9????????           |                     
            //   83bc24a801000001     | cmp                 dword ptr [esp + 0x1a8], 1

        $sequence_9 = { e8???????? 58 59 8b4b04 8b4308 833b01 7414 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   58                   | pop                 eax
            //   59                   | pop                 ecx
            //   8b4b04               | mov                 ecx, dword ptr [ebx + 4]
            //   8b4308               | mov                 eax, dword ptr [ebx + 8]
            //   833b01               | cmp                 dword ptr [ebx], 1
            //   7414                 | je                  0x16

    condition:
        7 of them and filesize < 598016
}