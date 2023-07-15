rule win_soraya_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.soraya."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.soraya"
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
        $sequence_0 = { ff15???????? 8d48bf 80f919 77f2 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   8d48bf               | lea                 ecx, [eax - 0x41]
            //   80f919               | cmp                 cl, 0x19
            //   77f2                 | ja                  0xfffffff4

        $sequence_1 = { 8d8c01ac73a6f2 8b45fc 8b55f8 05c53f0000 23c2 8bf9 }
            // n = 6, score = 100
            //   8d8c01ac73a6f2       | mov                 ecx, dword ptr [ebp - 4]
            //   8b45fc               | mov                 edx, dword ptr [ebp - 0x2c]
            //   8b55f8               | xor                 ecx, esi
            //   05c53f0000           | lea                 ecx, [ecx + edx - 0xdc102]
            //   23c2                 | cmp                 eax, ecx
            //   8bf9                 | jb                  0xfffffbb7

        $sequence_2 = { 7408 ffc3 3bdf 72f4 33db 85db 751e }
            // n = 7, score = 100
            //   7408                 | inc                 ecx
            //   ffc3                 | cmp                 ecx, edi
            //   3bdf                 | jb                  0xfffffff5
            //   72f4                 | je                  0xa
            //   33db                 | inc                 ebx
            //   85db                 | cmp                 ebx, edi
            //   751e                 | jb                  0xfffffff6

        $sequence_3 = { 8945f8 a1???????? 8b4df8 69c0a72b0000 05deacffff 3bc8 }
            // n = 6, score = 100
            //   8945f8               | jb                  0x27
            //   a1????????           |                     
            //   8b4df8               | je                  0x19
            //   69c0a72b0000         | inc                 eax
            //   05deacffff           | cmp                 edi, eax
            //   3bc8                 | je                  0x17

        $sequence_4 = { 0fafc1 8b4dfc 8b55d4 33ce 8d8c11fe3ef2ff 3bc1 0f82a0fbffff }
            // n = 7, score = 100
            //   0fafc1               | mov                 dword ptr [ebp - 0xc], 0x5f931
            //   8b4dfc               | mov                 edx, dword ptr [ebp + 0x28]
            //   8b55d4               | lodsb               al, byte ptr [esi]
            //   33ce                 | stosb               byte ptr es:[edi], al
            //   8d8c11fe3ef2ff       | cmp                 edi, edx
            //   3bc1                 | jae                 9
            //   0f82a0fbffff         | lea                 ebp, [esp + 0x40]

        $sequence_5 = { 664139840882010000 7530 ffc2 48ffc1 }
            // n = 4, score = 100
            //   664139840882010000     | inc    cx
            //   7530                 | cmp                 dword ptr [eax + ecx + 0x182], eax
            //   ffc2                 | jne                 0x32
            //   48ffc1               | inc                 edx

        $sequence_6 = { 50 50 6a4f 8d4da8 51 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   50                   | push                ebx
            //   6a4f                 | push                edi
            //   8d4da8               | push                dword ptr [ebp - 4]
            //   51                   | call                esi

        $sequence_7 = { 33db 85db 0f84dc020000 ba0a000000 498bcf e8???????? }
            // n = 6, score = 100
            //   33db                 | xor                 ebx, ebx
            //   85db                 | test                ebx, ebx
            //   0f84dc020000         | jne                 0x20
            //   ba0a000000           | xor                 ebx, ebx
            //   498bcf               | test                ebx, ebx
            //   e8????????           |                     

        $sequence_8 = { 48ffc6 4863c3 4883f810 72d6 }
            // n = 4, score = 100
            //   48ffc6               | dec                 ecx
            //   4863c3               | mov                 ecx, edi
            //   4883f810             | dec                 eax
            //   72d6                 | mov                 dword ptr [esp + 0x20], eax

        $sequence_9 = { 2b5634 81e1ff0f0000 034dec 0111 8b4804 ff45f8 }
            // n = 6, score = 100
            //   2b5634               | je                  0xf
            //   81e1ff0f0000         | movzx               edx, cx
            //   034dec               | jmp                 0x16
            //   0111                 | lea                 ecx, [eax - 0x41]
            //   8b4804               | cmp                 cl, 0x19
            //   ff45f8               | ja                  0xfffffff7

        $sequence_10 = { b9d3400000 660fafc1 0fb7c0 99 }
            // n = 4, score = 100
            //   b9d3400000           | push                esi
            //   660fafc1             | push                esi
            //   0fb7c0               | push                dword ptr [ebp + 8]
            //   99                   | jae                 0x45

        $sequence_11 = { 488bd6 ff15???????? 8d7b01 eb30 }
            // n = 4, score = 100
            //   488bd6               | dec                 eax
            //   ff15????????         |                     
            //   8d7b01               | lea                 ecx, [0xffffee49]
            //   eb30                 | dec                 eax

        $sequence_12 = { 33fe 2bd7 8b7df0 03d1 668917 8b55f4 }
            // n = 6, score = 100
            //   33fe                 | ret                 
            //   2bd7                 | push                ebp
            //   8b7df0               | mov                 ebp, esp
            //   03d1                 | sub                 esp, 0x30
            //   668917               | mov                 dword ptr [ebp - 0x14], 0x5f971
            //   8b55f4               | imul                eax, ecx

        $sequence_13 = { e8???????? 7343 e8???????? 7225 e8???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   7343                 | lea                 ecx, [ebp - 0x58]
            //   e8????????           |                     
            //   7225                 | push                ecx
            //   e8????????           |                     

        $sequence_14 = { 8d6c2440 c3 55 8bec 83ec30 c745ec71f90500 }
            // n = 6, score = 100
            //   8d6c2440             | imul                eax, eax, 0x2ba7
            //   c3                   | add                 eax, 0xffffacde
            //   55                   | cmp                 ecx, eax
            //   8bec                 | mov                 dword ptr [ebp - 0x28], 0xf0233e
            //   83ec30               | mov                 dword ptr [ebp - 0x24], 0
            //   c745ec71f90500       | mov                 dword ptr [ebp - 0x14], 0x5c971

        $sequence_15 = { c745d83e23f000 c745dc00000000 c745ec71c90500 c745f431f90500 }
            // n = 4, score = 100
            //   c745d83e23f000       | push                eax
            //   c745dc00000000       | push                dword ptr [ebp - 0x10]
            //   c745ec71c90500       | add                 edi, dword ptr [ebp - 8]
            //   c745f431f90500       | mov                 ecx, 0x40d3

        $sequence_16 = { 85ff 740d 42803c310a 7408 ffc1 3bcf 72f3 }
            // n = 7, score = 100
            //   85ff                 | dec                 eax
            //   740d                 | inc                 ecx
            //   42803c310a           | test                edi, edi
            //   7408                 | je                  0xf
            //   ffc1                 | inc                 edx
            //   3bcf                 | cmp                 byte ptr [ecx + esi], 0xa
            //   72f3                 | je                  0xa

        $sequence_17 = { ff15???????? 56 56 56 ff7508 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   56                   | inc                 dword ptr [ebp - 8]
            //   56                   | push                eax
            //   56                   | push                eax
            //   ff7508               | push                0x4f

        $sequence_18 = { 7417 40 3bf8 7412 }
            // n = 4, score = 100
            //   7417                 | je                  0xad
            //   40                   | push                ebx
            //   3bf8                 | push                edi
            //   7412                 | push                0x40

        $sequence_19 = { 0f84a7000000 53 57 6a40 6800300000 6800100000 }
            // n = 6, score = 100
            //   0f84a7000000         | test                eax, eax
            //   53                   | sub                 edx, dword ptr [esi + 0x34]
            //   57                   | and                 ecx, 0xfff
            //   6a40                 | add                 ecx, dword ptr [ebp - 0x14]
            //   6800300000           | add                 dword ptr [ecx], edx
            //   6800100000           | mov                 ecx, dword ptr [eax + 4]

        $sequence_20 = { 4889442420 ff15???????? 488d0d49eeffff e8???????? }
            // n = 4, score = 100
            //   4889442420           | je                  0x2e4
            //   ff15????????         |                     
            //   488d0d49eeffff       | mov                 edx, 0xa
            //   e8????????           |                     

        $sequence_21 = { 8b5528 ac aa 3bfa 7303 }
            // n = 5, score = 100
            //   8b5528               | imul                ax, cx
            //   ac                   | movzx               eax, ax
            //   aa                   | cdq                 
            //   3bfa                 | mov                 dword ptr [ebp - 8], eax
            //   7303                 | mov                 ecx, dword ptr [ebp - 8]

        $sequence_22 = { 50 53 bf???????? 57 ff75fc ffd6 85c0 }
            // n = 7, score = 100
            //   50                   | jmp                 0x35
            //   53                   | dec                 esp
            //   bf????????           |                     
            //   57                   | sub                 esi, ebx
            //   ff75fc               | mov                 eax, 0x80000000
            //   ffd6                 | dec                 eax
            //   85c0                 | test                eax, ecx

    condition:
        7 of them and filesize < 188416
}