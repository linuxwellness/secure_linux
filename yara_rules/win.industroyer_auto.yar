rule win_industroyer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.industroyer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.industroyer"
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
        $sequence_0 = { 8945e0 8945dc 33c0 668945d0 8d45f4 50 }
            // n = 6, score = 600
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   33c0                 | xor                 eax, eax
            //   668945d0             | mov                 word ptr [ebp - 0x30], ax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax

        $sequence_1 = { 6a10 50 e8???????? 8b5d08 83c410 814dd401010000 }
            // n = 6, score = 600
            //   6a10                 | push                0x10
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   83c410               | add                 esp, 0x10
            //   814dd401010000       | or                  dword ptr [ebp - 0x2c], 0x101

        $sequence_2 = { ff15???????? 50 ff7508 6a00 6a00 ff15???????? 85c0 }
            // n = 7, score = 600
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_3 = { 50 ff7508 ff750c e8???????? 83c40c 837d1000 }
            // n = 6, score = 600
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0

        $sequence_4 = { 6a44 5f 8d45a0 33f6 }
            // n = 4, score = 600
            //   6a44                 | push                0x44
            //   5f                   | pop                 edi
            //   8d45a0               | lea                 eax, [ebp - 0x60]
            //   33f6                 | xor                 esi, esi

        $sequence_5 = { ffd6 8d45fc 50 6a04 8d45f4 }
            // n = 5, score = 600
            //   ffd6                 | call                esi
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   6a04                 | push                4
            //   8d45f4               | lea                 eax, [ebp - 0xc]

        $sequence_6 = { 50 8d8584f5ffff 50 8d85a4fdffff 50 ff15???????? 837df000 }
            // n = 7, score = 600
            //   50                   | push                eax
            //   8d8584f5ffff         | lea                 eax, [ebp - 0xa7c]
            //   50                   | push                eax
            //   8d85a4fdffff         | lea                 eax, [ebp - 0x25c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   837df000             | cmp                 dword ptr [ebp - 0x10], 0

        $sequence_7 = { ff7508 33db 8bfb e8???????? 59 }
            // n = 5, score = 600
            //   ff7508               | push                dword ptr [ebp + 8]
            //   33db                 | xor                 ebx, ebx
            //   8bfb                 | mov                 edi, ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_8 = { 83c404 8bf0 8d45fc 6a00 50 }
            // n = 5, score = 400
            //   83c404               | add                 esp, 4
            //   8bf0                 | mov                 esi, eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_9 = { 8b859cefffff 0f44df 83c604 83fe08 72dd 84db 8b9d98efffff }
            // n = 7, score = 400
            //   8b859cefffff         | mov                 eax, dword ptr [ebp - 0x1064]
            //   0f44df               | cmove               ebx, edi
            //   83c604               | add                 esi, 4
            //   83fe08               | cmp                 esi, 8
            //   72dd                 | jb                  0xffffffdf
            //   84db                 | test                bl, bl
            //   8b9d98efffff         | mov                 ebx, dword ptr [ebp - 0x1068]

        $sequence_10 = { 8d442448 50 ffd6 85c0 7441 }
            // n = 5, score = 400
            //   8d442448             | lea                 eax, [esp + 0x48]
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7441                 | je                  0x43

        $sequence_11 = { bfffff0000 0f46f9 3d00005000 b900400000 0f46f9 3d00003000 }
            // n = 6, score = 400
            //   bfffff0000           | mov                 edi, 0xffff
            //   0f46f9               | cmovbe              edi, ecx
            //   3d00005000           | cmp                 eax, 0x500000
            //   b900400000           | mov                 ecx, 0x4000
            //   0f46f9               | cmovbe              edi, ecx
            //   3d00003000           | cmp                 eax, 0x300000

        $sequence_12 = { f644241810 751c 8d442444 50 57 8d842470020000 }
            // n = 6, score = 400
            //   f644241810           | test                byte ptr [esp + 0x18], 0x10
            //   751c                 | jne                 0x1e
            //   8d442444             | lea                 eax, [esp + 0x44]
            //   50                   | push                eax
            //   57                   | push                edi
            //   8d842470020000       | lea                 eax, [esp + 0x270]

        $sequence_13 = { 8b3d???????? 85c0 0f858c000000 0f1f8000000000 8d85a0fbffff 46 50 }
            // n = 7, score = 400
            //   8b3d????????         |                     
            //   85c0                 | test                eax, eax
            //   0f858c000000         | jne                 0x92
            //   0f1f8000000000       | nop                 dword ptr [eax]
            //   8d85a0fbffff         | lea                 eax, [ebp - 0x460]
            //   46                   | inc                 esi
            //   50                   | push                eax

        $sequence_14 = { 8d344502000000 56 e8???????? 56 8bd8 57 }
            // n = 6, score = 400
            //   8d344502000000       | lea                 esi, [eax*2 + 2]
            //   56                   | push                esi
            //   e8????????           |                     
            //   56                   | push                esi
            //   8bd8                 | mov                 ebx, eax
            //   57                   | push                edi

        $sequence_15 = { 683f010f00 6a00 8d85a0f3ffff 50 6802000080 ff15???????? 85c0 }
            // n = 7, score = 400
            //   683f010f00           | push                0xf013f
            //   6a00                 | push                0
            //   8d85a0f3ffff         | lea                 eax, [ebp - 0xc60]
            //   50                   | push                eax
            //   6802000080           | push                0x80000002
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_16 = { ff7708 ff15???????? 89442414 85c0 0f8498000000 68???????? 50 }
            // n = 7, score = 200
            //   ff7708               | push                dword ptr [edi + 8]
            //   ff15????????         |                     
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   85c0                 | test                eax, eax
            //   0f8498000000         | je                  0x9e
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_17 = { 83e801 7413 83e802 75cf }
            // n = 4, score = 200
            //   83e801               | sub                 eax, 1
            //   7413                 | je                  0x15
            //   83e802               | sub                 eax, 2
            //   75cf                 | jne                 0xffffffd1

        $sequence_18 = { c745e0f0ff4000 e9???????? c745e0f8ff4000 e9???????? c745e0e4ff4000 e9???????? }
            // n = 6, score = 200
            //   c745e0f0ff4000       | mov                 dword ptr [ebp - 0x20], 0x40fff0
            //   e9????????           |                     
            //   c745e0f8ff4000       | mov                 dword ptr [ebp - 0x20], 0x40fff8
            //   e9????????           |                     
            //   c745e0e4ff4000       | mov                 dword ptr [ebp - 0x20], 0x40ffe4
            //   e9????????           |                     

        $sequence_19 = { c7410c00000000 8b0a c6410504 8bce 8b02 c6400603 }
            // n = 6, score = 200
            //   c7410c00000000       | mov                 dword ptr [ecx + 0xc], 0
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   c6410504             | mov                 byte ptr [ecx + 5], 4
            //   8bce                 | mov                 ecx, esi
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   c6400603             | mov                 byte ptr [eax + 6], 3

        $sequence_20 = { 8b04cd24ee4000 5f 5e 5b }
            // n = 4, score = 200
            //   8b04cd24ee4000       | mov                 eax, dword ptr [ecx*8 + 0x40ee24]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_21 = { 83e23f 6bf230 c1f806 033485d01f0210 f6462d01 7414 e8???????? }
            // n = 7, score = 200
            //   83e23f               | and                 edx, 0x3f
            //   6bf230               | imul                esi, edx, 0x30
            //   c1f806               | sar                 eax, 6
            //   033485d01f0210       | add                 esi, dword ptr [eax*4 + 0x10021fd0]
            //   f6462d01             | test                byte ptr [esi + 0x2d], 1
            //   7414                 | je                  0x16
            //   e8????????           |                     

        $sequence_22 = { 50 ff15???????? 8b44241c 89442444 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   89442444             | mov                 dword ptr [esp + 0x44], eax

        $sequence_23 = { c745e0e0ff4000 e9???????? 83e80f 7451 }
            // n = 4, score = 200
            //   c745e0e0ff4000       | mov                 dword ptr [ebp - 0x20], 0x40ffe0
            //   e9????????           |                     
            //   83e80f               | sub                 eax, 0xf
            //   7451                 | je                  0x53

        $sequence_24 = { 8b45f0 8b4de8 8b0485d01f0210 f644012880 }
            // n = 4, score = 200
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   8b0485d01f0210       | mov                 eax, dword ptr [eax*4 + 0x10021fd0]
            //   f644012880           | test                byte ptr [ecx + eax + 0x28], 0x80

        $sequence_25 = { 50 ffd6 ff770c ff542414 83c404 ff742414 ff15???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   ff770c               | push                dword ptr [edi + 0xc]
            //   ff542414             | call                dword ptr [esp + 0x14]
            //   83c404               | add                 esp, 4
            //   ff742414             | push                dword ptr [esp + 0x14]
            //   ff15????????         |                     

        $sequence_26 = { 0fb705???????? 6689413c 0fb605???????? 88413e 0f1005???????? 0f118133010000 }
            // n = 6, score = 200
            //   0fb705????????       |                     
            //   6689413c             | mov                 word ptr [ecx + 0x3c], ax
            //   0fb605????????       |                     
            //   88413e               | mov                 byte ptr [ecx + 0x3e], al
            //   0f1005????????       |                     
            //   0f118133010000       | movups              xmmword ptr [ecx + 0x133], xmm0

        $sequence_27 = { c7410400000000 c7410800000000 8d8350020000 8d8f50020000 3bc8 743d }
            // n = 6, score = 200
            //   c7410400000000       | mov                 dword ptr [ecx + 4], 0
            //   c7410800000000       | mov                 dword ptr [ecx + 8], 0
            //   8d8350020000         | lea                 eax, [ebx + 0x250]
            //   8d8f50020000         | lea                 ecx, [edi + 0x250]
            //   3bc8                 | cmp                 ecx, eax
            //   743d                 | je                  0x3f

        $sequence_28 = { 83e801 0f8501010000 c745e0e4ff4000 8b4508 8bcf 8b7510 c745dc04000000 }
            // n = 7, score = 200
            //   83e801               | sub                 eax, 1
            //   0f8501010000         | jne                 0x107
            //   c745e0e4ff4000       | mov                 dword ptr [ebp - 0x20], 0x40ffe4
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8bcf                 | mov                 ecx, edi
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   c745dc04000000       | mov                 dword ptr [ebp - 0x24], 4

        $sequence_29 = { 8985ecfffeff 8bc8 c745fc00000000 e8???????? c745fcffffffff 8bd0 57 }
            // n = 7, score = 200
            //   8985ecfffeff         | mov                 dword ptr [ebp - 0x10014], eax
            //   8bc8                 | mov                 ecx, eax
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   e8????????           |                     
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8bd0                 | mov                 edx, eax
            //   57                   | push                edi

        $sequence_30 = { 8bf8 85ff 0f84c8000000 837c243c04 0f85bd000000 ff7704 }
            // n = 6, score = 200
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   0f84c8000000         | je                  0xce
            //   837c243c04           | cmp                 dword ptr [esp + 0x3c], 4
            //   0f85bd000000         | jne                 0xc3
            //   ff7704               | push                dword ptr [edi + 4]

        $sequence_31 = { 80780504 751b eb26 80780504 7513 83780800 750d }
            // n = 7, score = 200
            //   80780504             | cmp                 byte ptr [eax + 5], 4
            //   751b                 | jne                 0x1d
            //   eb26                 | jmp                 0x28
            //   80780504             | cmp                 byte ptr [eax + 5], 4
            //   7513                 | jne                 0x15
            //   83780800             | cmp                 dword ptr [eax + 8], 0
            //   750d                 | jne                 0xf

        $sequence_32 = { 50 c700???????? 895004 e8???????? 5e 5d c20400 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   c700????????         |                     
            //   895004               | mov                 dword ptr [eax + 4], edx
            //   e8????????           |                     
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4

        $sequence_33 = { 894598 3b4b3c 750c 51 8d4b34 e8???????? }
            // n = 6, score = 100
            //   894598               | mov                 dword ptr [ebp - 0x68], eax
            //   3b4b3c               | cmp                 ecx, dword ptr [ebx + 0x3c]
            //   750c                 | jne                 0xe
            //   51                   | push                ecx
            //   8d4b34               | lea                 ecx, [ebx + 0x34]
            //   e8????????           |                     

        $sequence_34 = { 6a0c 59 99 f7f9 8d4db8 8945e0 }
            // n = 6, score = 100
            //   6a0c                 | push                0xc
            //   59                   | pop                 ecx
            //   99                   | cdq                 
            //   f7f9                 | idiv                ecx
            //   8d4db8               | lea                 ecx, [ebp - 0x48]
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax

        $sequence_35 = { e9???????? ff715c 8b531c 8d4602 ff7170 }
            // n = 5, score = 100
            //   e9????????           |                     
            //   ff715c               | push                dword ptr [ecx + 0x5c]
            //   8b531c               | mov                 edx, dword ptr [ebx + 0x1c]
            //   8d4602               | lea                 eax, [esi + 2]
            //   ff7170               | push                dword ptr [ecx + 0x70]

        $sequence_36 = { 51 8bc8 e8???????? 8d45e4 8b4d94 50 83c118 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   8b4d94               | mov                 ecx, dword ptr [ebp - 0x6c]
            //   50                   | push                eax
            //   83c118               | add                 ecx, 0x18

        $sequence_37 = { 394f04 75df 84db 75db 56 e8???????? 59 }
            // n = 7, score = 100
            //   394f04               | cmp                 dword ptr [edi + 4], ecx
            //   75df                 | jne                 0xffffffe1
            //   84db                 | test                bl, bl
            //   75db                 | jne                 0xffffffdd
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_38 = { 8b7594 8bdf 895da0 ff759c 0fb7c3 }
            // n = 5, score = 100
            //   8b7594               | mov                 esi, dword ptr [ebp - 0x6c]
            //   8bdf                 | mov                 ebx, edi
            //   895da0               | mov                 dword ptr [ebp - 0x60], ebx
            //   ff759c               | push                dword ptr [ebp - 0x64]
            //   0fb7c3               | movzx               eax, bx

        $sequence_39 = { e8???????? ff7508 8d4dec ff75f8 ff75f4 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff75f4               | push                dword ptr [ebp - 0xc]

    condition:
        7 of them and filesize < 983040
}