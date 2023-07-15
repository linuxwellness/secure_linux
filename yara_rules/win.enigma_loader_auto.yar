rule win_enigma_loader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.enigma_loader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enigma_loader"
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
        $sequence_0 = { 4157 4883ec20 488b4108 4c8bf2 482b01 }
            // n = 5, score = 100
            //   4157                 | je                  0x1014
            //   4883ec20             | cmp                 eax, 4
            //   488b4108             | jne                 0x5eb
            //   4c8bf2               | dec                 ecx
            //   482b01               | lea                 edx, [edi + 0x98]

        $sequence_1 = { 90 488b5590 493bd5 722e 48ffc2 488b4c2478 488bc1 }
            // n = 7, score = 100
            //   90                   | lea                 edx, [ebp + 0x1e8]
            //   488b5590             | cmp                 eax, 0xb
            //   493bd5               | jne                 0x1939
            //   722e                 | dec                 ecx
            //   48ffc2               | mov                 ecx, esi
            //   488b4c2478           | test                al, al
            //   488bc1               | je                  0x19c6

        $sequence_2 = { e9???????? 488d8a38000000 e9???????? 488d8a78000000 e9???????? 488d8ad8000000 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   488d8a38000000       | mov                 edi, dword ptr [esp + 0x50]
            //   e9????????           |                     
            //   488d8a78000000       | mov                 edx, ebx
            //   e9????????           |                     
            //   488d8ad8000000       | mov                 ebp, 0xc0000001
            //   e9????????           |                     

        $sequence_3 = { 83e10f 4a0fbe841978940200 428a8c1988940200 4c2bc0 418b40fc d3e8 8bc8 }
            // n = 7, score = 100
            //   83e10f               | inc                 ecx
            //   4a0fbe841978940200     | mov    eax, eax
            //   428a8c1988940200     | sub                 eax, edx
            //   4c2bc0               | je                  0xbc
            //   418b40fc             | dec                 eax
            //   d3e8                 | mov                 dword ptr [esp + 8], ebx
            //   8bc8                 | push                edi

        $sequence_4 = { 0f1005???????? 8b05???????? 458bc6 0f100d???????? 894588 4c8d4c2450 0f11442450 }
            // n = 7, score = 100
            //   0f1005????????       |                     
            //   8b05????????         |                     
            //   458bc6               | lea                 edx, [ebp - 0x68]
            //   0f100d????????       |                     
            //   894588               | dec                 eax
            //   4c8d4c2450           | mov                 ecx, edi
            //   0f11442450           | nop                 

        $sequence_5 = { 48c7c102000080 ffd0 85c0 7921 bab9fa0e75 8bcf e8???????? }
            // n = 7, score = 100
            //   48c7c102000080       | jbe                 0x262
            //   ffd0                 | jmp                 0x196
            //   85c0                 | dec                 eax
            //   7921                 | test                eax, eax
            //   bab9fa0e75           | je                  0x1ed
            //   8bcf                 | dec                 eax
            //   e8????????           |                     

        $sequence_6 = { 4183f812 7cd0 bf05000000 eb2c 8bd7 488d0dede10200 e8???????? }
            // n = 7, score = 100
            //   4183f812             | movdqu              xmmword ptr [ebp - 0x80], xmm0
            //   7cd0                 | jne                 0x826
            //   bf05000000           | mov                 ebx, 0x1000
            //   eb2c                 | dec                 eax
            //   8bd7                 | mov                 edx, dword ptr [ebp - 0x70]
            //   488d0dede10200       | dec                 ecx
            //   e8????????           |                     

        $sequence_7 = { 85c0 746c 488d4c2430 eb49 ffc7 8bcf 83e901 }
            // n = 7, score = 100
            //   85c0                 | lea                 eax, [0xcbd2]
            //   746c                 | jne                 0x5fc
            //   488d4c2430           | inc                 eax
            //   eb49                 | mov                 byte ptr [ebp + 0x158], bh
            //   ffc7                 | dec                 esp
            //   8bcf                 | mov                 eax, dword ptr [esi]
            //   83e901               | inc                 ecx

        $sequence_8 = { 48894620 488bcb e8???????? 41894640 83f80c 0f858f020000 4088bd58020000 }
            // n = 7, score = 100
            //   48894620             | dec                 eax
            //   488bcb               | cmp                 eax, 0x1f
            //   e8????????           |                     
            //   41894640             | ja                  0x12da
            //   83f80c               | dec                 eax
            //   0f858f020000         | add                 edx, 0x27
            //   4088bd58020000       | dec                 eax

        $sequence_9 = { 483bc1 480f42e9 488d4d01 4881f900100000 720b 488d4127 483bc1 }
            // n = 7, score = 100
            //   483bc1               | movsx               eax, byte ptr [ecx + edx + 0x29478]
            //   480f42e9             | inc                 edx
            //   488d4d01             | mov                 cl, byte ptr [ecx + edx + 0x29488]
            //   4881f900100000       | dec                 esp
            //   720b                 | sub                 eax, eax
            //   488d4127             | inc                 ecx
            //   483bc1               | mov                 eax, dword ptr [eax - 4]

    condition:
        7 of them and filesize < 798720
}