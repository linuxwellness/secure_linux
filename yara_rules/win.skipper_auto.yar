rule win_skipper_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.skipper."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.skipper"
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
        $sequence_0 = { 6a03 68???????? 68???????? 6a50 }
            // n = 4, score = 600
            //   6a03                 | or                  eax, 0xffffff00
            //   68????????           |                     
            //   68????????           |                     
            //   6a50                 | inc                 ecx

        $sequence_1 = { 59 5d c3 55 8bec 33c0 50 }
            // n = 7, score = 500
            //   59                   | inc                 ecx
            //   5d                   | mov                 dword ptr [ebp - 0x118], ecx
            //   c3                   | or                  edx, 0xffffff00
            //   55                   | inc                 edx
            //   8bec                 | mov                 dword ptr [ebp - 4], edx
            //   33c0                 | movzx               eax, byte ptr [ebp - 8]
            //   50                   | mov                 cl, byte ptr [ebp + eax - 0x110]

        $sequence_2 = { e8???????? 6804010000 e8???????? 6804010000 8bf8 6a00 57 }
            // n = 7, score = 500
            //   e8????????           |                     
            //   6804010000           | push                eax
            //   e8????????           |                     
            //   6804010000           | add                 esp, 4
            //   8bf8                 | push                0
            //   6a00                 | push                0x64
            //   57                   | push                edx

        $sequence_3 = { ff15???????? 6a00 6a00 6a00 6a00 50 ff15???????? }
            // n = 7, score = 500
            //   ff15????????         |                     
            //   6a00                 | mov                 byte ptr [ebp - 0x111], cl
            //   6a00                 | movzx               eax, byte ptr [ebp - 0x112]
            //   6a00                 | xor                 edx, eax
            //   6a00                 | mov                 ecx, dword ptr [ebp + 0x18]
            //   50                   | add                 ecx, dword ptr [ebp - 0x124]
            //   ff15????????         |                     

        $sequence_4 = { 6804010000 6a00 50 8945e0 e8???????? }
            // n = 5, score = 400
            //   6804010000           | push                0
            //   6a00                 | push                3
            //   50                   | push                0x50
            //   8945e0               | push                3
            //   e8????????           |                     

        $sequence_5 = { 8945fc 53 56 57 8b7d10 89bdecfeffff }
            // n = 6, score = 400
            //   8945fc               | dec                 edx
            //   53                   | or                  edx, 0xffffff00
            //   56                   | or                  eax, 0xffffff00
            //   57                   | inc                 eax
            //   8b7d10               | mov                 dword ptr [ebp - 8], eax
            //   89bdecfeffff         | mov                 ecx, dword ptr [ebp - 8]

        $sequence_6 = { 57 e8???????? 57 6a08 68???????? b9???????? }
            // n = 6, score = 400
            //   57                   | push                edi
            //   e8????????           |                     
            //   57                   | mov                 byte ptr [ecx], dl
            //   6a08                 | cmp                 esi, 0x100
            //   68????????           |                     
            //   b9????????           |                     

        $sequence_7 = { 83c404 6a00 6a64 52 50 }
            // n = 5, score = 300
            //   83c404               | lea                 eax, [esp]
            //   6a00                 | dec                 eax
            //   6a64                 | lea                 edx, [esp]
            //   52                   | dec                 esp
            //   50                   | add                 eax, eax

        $sequence_8 = { 6800308000 6a00 6a00 68???????? }
            // n = 4, score = 300
            //   6800308000           | push                edi
            //   6a00                 | mov                 edi, ecx
            //   6a00                 | cmp                 edx, 4
            //   68????????           |                     

        $sequence_9 = { 2bc2 4863d0 420fb60432 4403c0 }
            // n = 4, score = 200
            //   2bc2                 | cmp                 dword ptr [eax + 0x23a6b8], edi
            //   4863d0               | je                  0xa4
            //   420fb60432           | mov                 dword ptr [ebp - 0x1c], eax
            //   4403c0               | cmp                 eax, 5

        $sequence_10 = { 68???????? 8b15???????? 52 68???????? e8???????? 83c414 }
            // n = 6, score = 200
            //   68????????           |                     
            //   8b15????????         |                     
            //   52                   | push                3
            //   68????????           |                     
            //   e8????????           |                     
            //   83c414               | push                0x50

        $sequence_11 = { 898ddcfeffff 8b95dcfeffff 3b5514 0f8dcf000000 8b45f8 }
            // n = 5, score = 200
            //   898ddcfeffff         | mov                 byte ptr [edx], al
            //   8b95dcfeffff         | inc                 eax
            //   3b5514               | dec                 eax
            //   0f8dcf000000         | lea                 edx, [edx + 1]
            //   8b45f8               | cmp                 eax, 0x100

        $sequence_12 = { 0fb6c1 4c8d0424 488d1424 4c03c0 }
            // n = 4, score = 200
            //   0fb6c1               | add                 esi, dword ptr [eax*4 + 0x23b720]
            //   4c8d0424             | mov                 eax, dword ptr [ebp - 0x1c]
            //   488d1424             | je                  0x58
            //   4c03c0               | mov                 ecx, dword ptr [ebp - 0x20]

        $sequence_13 = { 7908 49 81c900ffffff 41 898de8feffff }
            // n = 5, score = 200
            //   7908                 | inc                 ecx
            //   49                   | and                 edx, 0x800000ff
            //   81c900ffffff         | jge                 0x20
            //   41                   | inc                 ecx
            //   898de8feffff         | dec                 edx

        $sequence_14 = { 8b85e0feffff 99 f77d0c 8b4508 0fb61410 }
            // n = 5, score = 200
            //   8b85e0feffff         | push                0
            //   99                   | push                0
            //   f77d0c               | push                0
            //   8b4508               | push                0
            //   0fb61410             | push                0

        $sequence_15 = { 7d0d 41ffc8 4181c800ffffff 41ffc0 410fb6c0 488d1424 }
            // n = 6, score = 200
            //   7d0d                 | mov                 eax, dword ptr [ebp + 8]
            //   41ffc8               | push                eax
            //   4181c800ffffff       | push                0
            //   41ffc0               | sar                 eax, 5
            //   410fb6c0             | and                 esi, 0x1f
            //   488d1424             | shl                 esi, 6

        $sequence_16 = { 4863c1 0fb61404 4403d2 4181e2ff000080 7d0d 41ffca }
            // n = 6, score = 200
            //   4863c1               | jge                 0x18
            //   0fb61404             | mov                 cx, word ptr [ebx + eax*2 + 0x10]
            //   4403d2               | mov                 word ptr [eax*2 + 0x23b290], cx
            //   4181e2ff000080       | inc                 eax
            //   7d0d                 | jmp                 0
            //   41ffca               | dec                 eax

        $sequence_17 = { ffc9 81c900ffffff ffc1 4863c1 0fb61404 }
            // n = 5, score = 200
            //   ffc9                 | lea                 ecx, [ecx*4 + 0x23b720]
            //   81c900ffffff         | mov                 dword ptr [ecx], eax
            //   ffc1                 | lea                 edx, [eax + 0x800]
            //   4863c1               | push                0x104
            //   0fb61404             | lea                 eax, [ebp - 0x110]

        $sequence_18 = { 44880a 410fb610 4103d1 81e2ff000080 7d0a }
            // n = 5, score = 200
            //   44880a               | push                eax
            //   410fb610             | mov                 ecx, dword ptr [ebp - 0x128]
            //   4103d1               | xor                 eax, eax
            //   81e2ff000080         | mov                 dword ptr [ebp - 0x1c], esi
            //   7d0a                 | xor                 eax, eax

        $sequence_19 = { 7908 4a 81ca00ffffff 42 0fb6d2 8a8415f0feffff 8885eefeffff }
            // n = 7, score = 200
            //   7908                 | jl                  8
            //   4a                   | inc                 esp
            //   81ca00ffffff         | mov                 eax, ecx
            //   42                   | push                3
            //   0fb6d2               | push                0x50
            //   8a8415f0feffff       | push                0
            //   8885eefeffff         | push                0

        $sequence_20 = { 0fb6940df0feffff 0355fc 81e2ff000080 7908 4a 81ca00ffffff }
            // n = 6, score = 200
            //   0fb6940df0feffff     | push                3
            //   0355fc               | push                0x50
            //   81e2ff000080         | push                0
            //   7908                 | push                3
            //   4a                   | push                0x50
            //   81ca00ffffff         | add                 esp, 4

        $sequence_21 = { e8???????? 4c8d9c2410010000 498b5b10 498b6b18 498b7320 498b7b28 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   4c8d9c2410010000     | add                 edx, eax
            //   498b5b10             | movzx               eax, byte ptr [edx]
            //   498b6b18             | inc                 ecx
            //   498b7320             | mov                 byte ptr [eax], al
            //   498b7b28             | inc                 esp

        $sequence_22 = { 81ca00ffffff 42 8955fc 0fb645f8 8a8c05f0feffff 888deffeffff }
            // n = 6, score = 200
            //   81ca00ffffff         | dec                 esp
            //   42                   | lea                 ebx, [esp + 0x110]
            //   8955fc               | dec                 ecx
            //   0fb645f8             | mov                 ebx, dword ptr [ebx + 0x10]
            //   8a8c05f0feffff       | dec                 ecx
            //   888deffeffff         | mov                 ebp, dword ptr [ebx + 0x18]

        $sequence_23 = { 0fb685eefeffff 33d0 8b4d18 038ddcfeffff 8811 e9???????? }
            // n = 6, score = 200
            //   0fb685eefeffff       | dec                 ecx
            //   33d0                 | mov                 esi, dword ptr [ebx + 0x20]
            //   8b4d18               | dec                 ecx
            //   038ddcfeffff         | mov                 edi, dword ptr [ebx + 0x28]
            //   8811                 | nop                 dword ptr [eax + eax]
            //   e9????????           |                     

        $sequence_24 = { 4803d0 0fb602 418800 44880a 410fb610 }
            // n = 5, score = 200
            //   4803d0               | mov                 ecx, dword ptr [ebp - 0x11c]
            //   0fb602               | je                  0xe
            //   418800               | mov                 dword ptr [ebp - 0x12c], 0x43a
            //   44880a               | jmp                 0x18
            //   410fb610             | mov                 dword ptr [ebp - 0x12c], 0x1fffff

        $sequence_25 = { e8???????? 33c0 e9???????? 8975e4 33c0 39b8b8a62300 0f8491000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   33c0                 | mov                 si, word ptr [ecx]
            //   e9????????           |                     
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   33c0                 | mov                 esi, dword ptr [ebp + 8]
            //   39b8b8a62300         | mov                 dword ptr [esi + 0x5c], 0x2381d8
            //   0f8491000000         | xor                 edi, edi

        $sequence_26 = { c1f805 83e61f c1e606 03348520b72300 8b45e4 }
            // n = 5, score = 100
            //   c1f805               | dec                 eax
            //   83e61f               | xor                 ecx, esp
            //   c1e606               | dec                 eax
            //   03348520b72300       | lea                 edi, [0xe894]
            //   8b45e4               | inc                 ecx

        $sequence_27 = { 740c c785d4feffff3a040000 eb0a c785d4feffffffff1f00 8b4508 50 6a00 }
            // n = 7, score = 100
            //   740c                 | jmp                 0x28
            //   c785d4feffff3a040000     | dec    eax
            //   eb0a                 | mov                 edx, ebx
            //   c785d4feffffffff1f00     | dec    eax
            //   8b4508               | mov                 ecx, edi
            //   50                   | dec                 eax
            //   6a00                 | mov                 ecx, dword ptr [esp + 0x200]

        $sequence_28 = { 8945e4 8b7508 c7465cd8812300 33ff 47 897e14 85c0 }
            // n = 7, score = 100
            //   8945e4               | dec                 eax
            //   8b7508               | lea                 eax, [esp + 0xf0]
            //   c7465cd8812300       | ret                 
            //   33ff                 | dec                 eax
            //   47                   | mov                 dword ptr [esp + 8], ebx
            //   897e14               | push                edi
            //   85c0                 | dec                 eax

        $sequence_29 = { 6a06 89430c 8d4310 8d89bca62300 5a 668b31 }
            // n = 6, score = 100
            //   6a06                 | dec                 eax
            //   89430c               | mov                 dword ptr [esp + 0x200], eax
            //   8d4310               | mov                 ebx, ecx
            //   8d89bca62300         | dec                 eax
            //   5a                   | lea                 edx, [esp + 0xf0]
            //   668b31               | mov                 ecx, 0x104

        $sequence_30 = { 6804010000 8d85f0feffff 50 8b8dd8feffff }
            // n = 4, score = 100
            //   6804010000           | mov                 dword ptr [ebx + 0xc], eax
            //   8d85f0feffff         | lea                 eax, [ebx + 0x10]
            //   50                   | lea                 ecx, [ecx + 0x23a6bc]
            //   8b8dd8feffff         | pop                 edx

        $sequence_31 = { 4883c014 8938 e8???????? 488d1d2baa0000 4885c0 7404 }
            // n = 6, score = 100
            //   4883c014             | inc                 ecx
            //   8938                 | mov                 ecx, 0x3000
            //   e8????????           |                     
            //   488d1d2baa0000       | inc                 ecx
            //   4885c0               | mov                 eax, 0x104
            //   7404                 | dec                 eax

        $sequence_32 = { 75f6 488b0d???????? 33d2 41b894000000 488908 8b0d???????? }
            // n = 6, score = 100
            //   75f6                 | dec                 eax
            //   488b0d????????       |                     
            //   33d2                 | test                esi, esi
            //   41b894000000         | je                  0x25
            //   488908               | dec                 eax
            //   8b0d????????         |                     

        $sequence_33 = { 7456 8b4de0 8d0c8d20b72300 8901 8305????????20 8d9000080000 }
            // n = 6, score = 100
            //   7456                 | mov                 eax, 0x104
            //   8b4de0               | xor                 ecx, ecx
            //   8d0c8d20b72300       | dec                 eax
            //   8901                 | mov                 edx, edi
            //   8305????????20       |                     
            //   8d9000080000         | push                6

        $sequence_34 = { 33d2 ff15???????? 33d2 41b900300000 }
            // n = 4, score = 100
            //   33d2                 | mov                 ebp, edi
            //   ff15????????         |                     
            //   33d2                 | dec                 eax
            //   41b900300000         | mov                 esi, dword ptr [ebx]

        $sequence_35 = { 488d0590a50000 488b4c2430 483bc8 7405 e8???????? 488b05???????? }
            // n = 6, score = 100
            //   488d0590a50000       | dec                 eax
            //   488b4c2430           | lea                 eax, [0xa590]
            //   483bc8               | dec                 eax
            //   7405                 | mov                 ecx, dword ptr [esp + 0x30]
            //   e8????????           |                     
            //   488b05????????       |                     

        $sequence_36 = { bf24000000 488d1d24a50000 8bef 488b33 4885f6 741b }
            // n = 6, score = 100
            //   bf24000000           | dec                 eax
            //   488d1d24a50000       | cmp                 ecx, eax
            //   8bef                 | je                  0xa
            //   488b33               | mov                 edi, 0x24
            //   4885f6               | dec                 eax
            //   741b                 | lea                 ebx, [0xa524]

        $sequence_37 = { 488bd3 488bcf ff15???????? 488b8c2400020000 4833cc }
            // n = 5, score = 100
            //   488bd3               | dec                 eax
            //   488bcf               | cmp                 ecx, eax
            //   ff15????????         |                     
            //   488b8c2400020000     | jne                 0xfffffff8
            //   4833cc               | xor                 edx, edx

        $sequence_38 = { 4889842400020000 8bd9 488d9424f0000000 b904010000 ff15???????? 488d8424f0000000 }
            // n = 6, score = 100
            //   4889842400020000     | add                 eax, 0x14
            //   8bd9                 | mov                 dword ptr [eax], edi
            //   488d9424f0000000     | dec                 eax
            //   b904010000           | lea                 ebx, [0xaa2b]
            //   ff15????????         |                     
            //   488d8424f0000000     | dec                 eax

        $sequence_39 = { c3 48895c2408 57 4883ec20 488d1de7a40000 488d3de0a40000 eb0e }
            // n = 7, score = 100
            //   c3                   | test                eax, eax
            //   48895c2408           | je                  0x12
            //   57                   | jne                 0x18
            //   4883ec20             | dec                 eax
            //   488d1de7a40000       | lea                 eax, [0xa590]
            //   488d3de0a40000       | dec                 eax
            //   eb0e                 | mov                 ecx, dword ptr [esp + 0x30]

        $sequence_40 = { c6450800 720b ff7520 e8???????? 83c404 837d4c10 }
            // n = 6, score = 100
            //   c6450800             | jb                  0x3f
            //   720b                 | neg                 ecx
            //   ff7520               | and                 ecx, 3
            //   e8????????           |                     
            //   83c404               | push                3
            //   837d4c10             | push                0x50

        $sequence_41 = { 0f84ab000000 80bddcfeffff00 7504 33c9 eb19 }
            // n = 5, score = 100
            //   0f84ab000000         | push                0
            //   80bddcfeffff00       | push                0
            //   7504                 | push                3
            //   33c9                 | push                0x50
            //   eb19                 | push                0

        $sequence_42 = { 6800800000 6804010000 8b85d8feffff 50 8b8de4feffff }
            // n = 5, score = 100
            //   6800800000           | sub                 esp, 0x20
            //   6804010000           | dec                 eax
            //   8b85d8feffff         | lea                 ebx, [0xa4e7]
            //   50                   | dec                 eax
            //   8b8de4feffff         | lea                 edi, [0xa4e0]

        $sequence_43 = { 81fa80000000 7c0e 0fba25????????01 0f82cb5c0000 57 8bf9 }
            // n = 6, score = 100
            //   81fa80000000         | push                3
            //   7c0e                 | push                0x50
            //   0fba25????????01     |                     
            //   0f82cb5c0000         | push                0x104
            //   57                   | push                0x104
            //   8bf9                 | mov                 edi, eax

    condition:
        7 of them and filesize < 262144
}