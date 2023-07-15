rule win_teleport_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.teleport."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.teleport"
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
        $sequence_0 = { ffd7 85c0 7fe9 68f4010000 ff15???????? }
            // n = 5, score = 100
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   7fe9                 | jg                  0xffffffeb
            //   68f4010000           | push                0x1f4
            //   ff15????????         |                     

        $sequence_1 = { 8b45f8 83f202 33c2 895720 33f0 894724 8945f8 }
            // n = 7, score = 100
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   83f202               | xor                 edx, 2
            //   33c2                 | xor                 eax, edx
            //   895720               | mov                 dword ptr [edi + 0x20], edx
            //   33f0                 | xor                 esi, eax
            //   894724               | mov                 dword ptr [edi + 0x24], eax
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_2 = { 83c404 8985f4feffff c7401400000000 c7401807000000 66894804 897020 }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   8985f4feffff         | mov                 dword ptr [ebp - 0x10c], eax
            //   c7401400000000       | mov                 dword ptr [eax + 0x14], 0
            //   c7401807000000       | mov                 dword ptr [eax + 0x18], 7
            //   66894804             | mov                 word ptr [eax + 4], cx
            //   897020               | mov                 dword ptr [eax + 0x20], esi

        $sequence_3 = { 331485a0fa4200 8bc3 c1e810 0fb6c0 331485a0fe4200 0fb6c1 c1e908 }
            // n = 7, score = 100
            //   331485a0fa4200       | xor                 edx, dword ptr [eax*4 + 0x42faa0]
            //   8bc3                 | mov                 eax, ebx
            //   c1e810               | shr                 eax, 0x10
            //   0fb6c0               | movzx               eax, al
            //   331485a0fe4200       | xor                 edx, dword ptr [eax*4 + 0x42fea0]
            //   0fb6c1               | movzx               eax, cl
            //   c1e908               | shr                 ecx, 8

        $sequence_4 = { 8b55d4 8a07 8b0c95e83e4300 8844192e 8b0495e83e4300 }
            // n = 5, score = 100
            //   8b55d4               | mov                 edx, dword ptr [ebp - 0x2c]
            //   8a07                 | mov                 al, byte ptr [edi]
            //   8b0c95e83e4300       | mov                 ecx, dword ptr [edx*4 + 0x433ee8]
            //   8844192e             | mov                 byte ptr [ecx + ebx + 0x2e], al
            //   8b0495e83e4300       | mov                 eax, dword ptr [edx*4 + 0x433ee8]

        $sequence_5 = { 8d85f0f7ffff d1f9 51 50 8d4e70 e8???????? 83be8000000000 }
            // n = 7, score = 100
            //   8d85f0f7ffff         | lea                 eax, [ebp - 0x810]
            //   d1f9                 | sar                 ecx, 1
            //   51                   | push                ecx
            //   50                   | push                eax
            //   8d4e70               | lea                 ecx, [esi + 0x70]
            //   e8????????           |                     
            //   83be8000000000       | cmp                 dword ptr [esi + 0x80], 0

        $sequence_6 = { 8b95ccfeffff eb0c 8b55e0 8b7de4 8995ccfeffff 8bc2 }
            // n = 6, score = 100
            //   8b95ccfeffff         | mov                 edx, dword ptr [ebp - 0x134]
            //   eb0c                 | jmp                 0xe
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   8b7de4               | mov                 edi, dword ptr [ebp - 0x1c]
            //   8995ccfeffff         | mov                 dword ptr [ebp - 0x134], edx
            //   8bc2                 | mov                 eax, edx

        $sequence_7 = { 330c85a0f64200 8bc2 334fd0 c1e810 0fb6c0 894dec 8bcb }
            // n = 7, score = 100
            //   330c85a0f64200       | xor                 ecx, dword ptr [eax*4 + 0x42f6a0]
            //   8bc2                 | mov                 eax, edx
            //   334fd0               | xor                 ecx, dword ptr [edi - 0x30]
            //   c1e810               | shr                 eax, 0x10
            //   0fb6c0               | movzx               eax, al
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   8bcb                 | mov                 ecx, ebx

        $sequence_8 = { 0fb6c2 331c8560b64200 8b45e8 335de4 899880000000 335de0 899884000000 }
            // n = 7, score = 100
            //   0fb6c2               | movzx               eax, dl
            //   331c8560b64200       | xor                 ebx, dword ptr [eax*4 + 0x42b660]
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   335de4               | xor                 ebx, dword ptr [ebp - 0x1c]
            //   899880000000         | mov                 dword ptr [eax + 0x80], ebx
            //   335de0               | xor                 ebx, dword ptr [ebp - 0x20]
            //   899884000000         | mov                 dword ptr [eax + 0x84], ebx

        $sequence_9 = { 6a28 85f6 7440 c745b480b54200 e8???????? 8945a8 83c404 }
            // n = 7, score = 100
            //   6a28                 | push                0x28
            //   85f6                 | test                esi, esi
            //   7440                 | je                  0x42
            //   c745b480b54200       | mov                 dword ptr [ebp - 0x4c], 0x42b580
            //   e8????????           |                     
            //   8945a8               | mov                 dword ptr [ebp - 0x58], eax
            //   83c404               | add                 esp, 4

    condition:
        7 of them and filesize < 458752
}