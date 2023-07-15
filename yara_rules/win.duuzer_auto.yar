rule win_duuzer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.duuzer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.duuzer"
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
        $sequence_0 = { 83f804 7408 83c8ff e9???????? }
            // n = 4, score = 200
            //   83f804               | cmp                 eax, 4
            //   7408                 | je                  0xa
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     

        $sequence_1 = { 0145f0 1155f4 85c9 7533 }
            // n = 4, score = 100
            //   0145f0               | mov                 edx, dword ptr [edi + 0x50]
            //   1155f4               | dec                 esp
            //   85c9                 | mov                 ecx, eax
            //   7533                 | inc                 ecx

        $sequence_2 = { 00f4 c640001c c740008a460323 d188470383ee }
            // n = 4, score = 100
            //   00f4                 | mov                 edx, dword ptr [ecx + 0x10]
            //   c640001c             | inc                 ebx
            //   c740008a460323       | mov                 byte ptr [ebx + edx], al
            //   d188470383ee         | inc                 dword ptr [ecx + 0x28]

        $sequence_3 = { 4c8b5c2420 b88bffffff 4c3b1d???????? b9cd000000 }
            // n = 4, score = 100
            //   4c8b5c2420           | dec                 eax
            //   b88bffffff           | mov                 edx, dword ptr [esp + 0x70]
            //   4c3b1d????????       |                     
            //   b9cd000000           | dec                 eax

        $sequence_4 = { 4c8b1f 45396b18 0f8442010000 488d1dbf49feff e9???????? }
            // n = 5, score = 100
            //   4c8b1f               | dec                 esp
            //   45396b18             | mov                 ebx, dword ptr [edi]
            //   0f8442010000         | inc                 ebp
            //   488d1dbf49feff       | cmp                 dword ptr [ebx + 0x18], ebp
            //   e9????????           |                     

        $sequence_5 = { 010b 014e4c 014e48 014e54 }
            // n = 4, score = 100
            //   010b                 | movzx               eax, byte ptr [ecx + 0x1711]
            //   014e4c               | dec                 esp
            //   014e48               | mov                 edx, dword ptr [ecx + 0x10]
            //   014e54               | inc                 ebx

        $sequence_6 = { 4c8b1f 45396b18 410f95c5 418d4502 eb56 }
            // n = 5, score = 100
            //   4c8b1f               | cmp                 dword ptr [edi + 0x90], ebp
            //   45396b18             | dec                 esp
            //   410f95c5             | mov                 ebx, dword ptr [edi]
            //   418d4502             | inc                 ebp
            //   eb56                 | cmp                 dword ptr [ebx + 0x18], ebp

        $sequence_7 = { 4c8b5750 4c8bc8 410fb65402ff 498d4c02ff }
            // n = 4, score = 100
            //   4c8b5750             | mov                 edx, dword ptr [esp + 0x70]
            //   4c8bc8               | dec                 eax
            //   410fb65402ff         | mov                 ecx, edi
            //   498d4c02ff           | dec                 esp

        $sequence_8 = { 00e0 3541000436 41 0023 }
            // n = 4, score = 100
            //   00e0                 | dec                 esp
            //   3541000436           | mov                 ecx, dword ptr [esp + 0x68]
            //   41                   | dec                 esp
            //   0023                 | mov                 eax, dword ptr [esp + 0x60]

        $sequence_9 = { 014dec 66837dec00 0f8efc010000 0fbf45ec }
            // n = 4, score = 100
            //   014dec               | mov                 ebx, dword ptr [esp + 0x28]
            //   66837dec00           | inc                 ecx
            //   0f8efc010000         | cmp                 dword ptr [ebx + 8], 0
            //   0fbf45ec             | jne                 0x20

        $sequence_10 = { 014dec 83bf8400000000 7708 398780000000 }
            // n = 4, score = 100
            //   014dec               | inc                 esi
            //   83bf8400000000       | add                 al, ah
            //   7708                 | xor                 eax, 0x36040041
            //   398780000000         | inc                 ecx

        $sequence_11 = { 4c8b4330 448b4b28 4d85c0 0f8591000000 }
            // n = 4, score = 100
            //   4c8b4330             | setne               ch
            //   448b4b28             | inc                 ecx
            //   4d85c0               | lea                 eax, [ebp + 2]
            //   0f8591000000         | jmp                 0x64

        $sequence_12 = { 4c8b442460 488b542470 488bcf e8???????? }
            // n = 4, score = 100
            //   4c8b442460           | inc                 ecx
            //   488b542470           | lea                 eax, [ebp + 2]
            //   488bcf               | jmp                 0x67
            //   e8????????           |                     

        $sequence_13 = { 01442410 3bfb 75c4 8b4630 }
            // n = 4, score = 100
            //   01442410             | mov                 byte ptr [ebx + edx], al
            //   3bfb                 | inc                 dword ptr [ecx + 0x28]
            //   75c4                 | movzx               eax, byte ptr [ecx + 0x1711]
            //   8b4630               | jmp                 0x1c

        $sequence_14 = { 4c8b5110 43880413 ff4128 0fb68111170000 }
            // n = 4, score = 100
            //   4c8b5110             | dec                 ebp
            //   43880413             | test                eax, eax
            //   ff4128               | jne                 0x9e
            //   0fb68111170000       | dec                 eax

    condition:
        7 of them and filesize < 491520
}