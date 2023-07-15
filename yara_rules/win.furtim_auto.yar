rule win_furtim_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.furtim."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.furtim"
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
        $sequence_0 = { ff96a4060000 85c0 7435 8d542438 8bce }
            // n = 5, score = 100
            //   ff96a4060000         | call                dword ptr [esi + 0x6a4]
            //   85c0                 | test                eax, eax
            //   7435                 | je                  0x37
            //   8d542438             | lea                 edx, [esp + 0x38]
            //   8bce                 | mov                 ecx, esi

        $sequence_1 = { 55 8bec 8b4508 56 8d34c5d0404100 833e00 7513 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   8d34c5d0404100       | lea                 esi, [eax*8 + 0x4140d0]
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7513                 | jne                 0x15

        $sequence_2 = { c786f0050000d9a74000 c786940000000fa04000 c786cc020000ab904000 c786dc02000037b24000 8bce c78698020000cbbf4000 }
            // n = 6, score = 100
            //   c786f0050000d9a74000     | mov    dword ptr [esi + 0x5f0], 0x40a7d9
            //   c786940000000fa04000     | mov    dword ptr [esi + 0x94], 0x40a00f
            //   c786cc020000ab904000     | mov    dword ptr [esi + 0x2cc], 0x4090ab
            //   c786dc02000037b24000     | mov    dword ptr [esi + 0x2dc], 0x40b237
            //   8bce                 | mov                 ecx, esi
            //   c78698020000cbbf4000     | mov    dword ptr [esi + 0x298], 0x40bfcb

        $sequence_3 = { 7565 8d45dc 50 6800010800 8d45fc 50 ff96b8030000 }
            // n = 7, score = 100
            //   7565                 | jne                 0x67
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   50                   | push                eax
            //   6800010800           | push                0x80100
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   ff96b8030000         | call                dword ptr [esi + 0x3b8]

        $sequence_4 = { ff9668040000 8907 8dbe70030000 833f00 750f 68???????? 53 }
            // n = 7, score = 100
            //   ff9668040000         | call                dword ptr [esi + 0x468]
            //   8907                 | mov                 dword ptr [edi], eax
            //   8dbe70030000         | lea                 edi, [esi + 0x370]
            //   833f00               | cmp                 dword ptr [edi], 0
            //   750f                 | jne                 0x11
            //   68????????           |                     
            //   53                   | push                ebx

        $sequence_5 = { 8bce ff96cc020000 8bcf 8ad8 ff563c 8ac3 5f }
            // n = 7, score = 100
            //   8bce                 | mov                 ecx, esi
            //   ff96cc020000         | call                dword ptr [esi + 0x2cc]
            //   8bcf                 | mov                 ecx, edi
            //   8ad8                 | mov                 bl, al
            //   ff563c               | call                dword ptr [esi + 0x3c]
            //   8ac3                 | mov                 al, bl
            //   5f                   | pop                 edi

        $sequence_6 = { 8b55fc 83e6f8 33c9 8b3c8a 83e7f8 }
            // n = 5, score = 100
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   83e6f8               | and                 esi, 0xfffffff8
            //   33c9                 | xor                 ecx, ecx
            //   8b3c8a               | mov                 edi, dword ptr [edx + ecx*4]
            //   83e7f8               | and                 edi, 0xfffffff8

        $sequence_7 = { 0f8412feffff 8b4c2414 ff563c 8b4c2418 ff563c 8d4c241c ff9608070000 }
            // n = 7, score = 100
            //   0f8412feffff         | je                  0xfffffe18
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   ff563c               | call                dword ptr [esi + 0x3c]
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   ff563c               | call                dword ptr [esi + 0x3c]
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   ff9608070000         | call                dword ptr [esi + 0x708]

        $sequence_8 = { 68???????? 56 ff901c070000 8b45f8 8b4df8 83c40c }
            // n = 6, score = 100
            //   68????????           |                     
            //   56                   | push                esi
            //   ff901c070000         | call                dword ptr [eax + 0x71c]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   83c40c               | add                 esp, 0xc

        $sequence_9 = { 56 57 6a28 be00010000 56 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a28                 | push                0x28
            //   be00010000           | mov                 esi, 0x100
            //   56                   | push                esi

    condition:
        7 of them and filesize < 622592
}