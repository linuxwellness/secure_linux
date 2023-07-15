rule win_jaku_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.jaku."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jaku"
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
        $sequence_0 = { 895df4 c70604000000 f6461104 745f 83ff10 7321 }
            // n = 6, score = 1500
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   c70604000000         | mov                 dword ptr [esi], 4
            //   f6461104             | test                byte ptr [esi + 0x11], 4
            //   745f                 | je                  0x61
            //   83ff10               | cmp                 edi, 0x10
            //   7321                 | jae                 0x23

        $sequence_1 = { 76ef 8b7d08 33f6 3bd6 7e10 3bfe 7404 }
            // n = 7, score = 1500
            //   76ef                 | jbe                 0xfffffff1
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   33f6                 | xor                 esi, esi
            //   3bd6                 | cmp                 edx, esi
            //   7e10                 | jle                 0x12
            //   3bfe                 | cmp                 edi, esi
            //   7404                 | je                  6

        $sequence_2 = { 56 e8???????? 59 894660 59 837e6003 0f8223010000 }
            // n = 7, score = 1500
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   894660               | mov                 dword ptr [esi + 0x60], eax
            //   59                   | pop                 ecx
            //   837e6003             | cmp                 dword ptr [esi + 0x60], 3
            //   0f8223010000         | jb                  0x129

        $sequence_3 = { 83ec78 53 56 8b7510 57 }
            // n = 5, score = 1500
            //   83ec78               | sub                 esp, 0x78
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   57                   | push                edi

        $sequence_4 = { 4e 75ef 8b7d18 6a0f }
            // n = 4, score = 1500
            //   4e                   | dec                 esi
            //   75ef                 | jne                 0xfffffff1
            //   8b7d18               | mov                 edi, dword ptr [ebp + 0x18]
            //   6a0f                 | push                0xf

        $sequence_5 = { 8b451c c745f013000000 8945e0 8945dc 8b4d14 6a01 }
            // n = 6, score = 1500
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]
            //   c745f013000000       | mov                 dword ptr [ebp - 0x10], 0x13
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   6a01                 | push                1

        $sequence_6 = { 41 3b4d14 7c02 33c9 46 }
            // n = 5, score = 1500
            //   41                   | inc                 ecx
            //   3b4d14               | cmp                 ecx, dword ptr [ebp + 0x14]
            //   7c02                 | jl                  4
            //   33c9                 | xor                 ecx, ecx
            //   46                   | inc                 esi

        $sequence_7 = { 50 e8???????? 83c410 3bc7 7564 }
            // n = 5, score = 1500
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   3bc7                 | cmp                 eax, edi
            //   7564                 | jne                 0x66

        $sequence_8 = { 68???????? ff15???????? c3 b8???????? e8???????? 83ec2c }
            // n = 6, score = 800
            //   68????????           |                     
            //   ff15????????         |                     
            //   c3                   | ret                 
            //   b8????????           |                     
            //   e8????????           |                     
            //   83ec2c               | sub                 esp, 0x2c

        $sequence_9 = { ff742408 e8???????? c20800 8bc1 }
            // n = 4, score = 600
            //   ff742408             | push                dword ptr [esp + 8]
            //   e8????????           |                     
            //   c20800               | ret                 8
            //   8bc1                 | mov                 eax, ecx

        $sequence_10 = { 6a01 03c3 68???????? 50 e8???????? 83c40c }
            // n = 6, score = 500
            //   6a01                 | push                1
            //   03c3                 | add                 eax, ebx
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_11 = { 7507 b800308000 eb02 33c0 }
            // n = 4, score = 500
            //   7507                 | jne                 9
            //   b800308000           | mov                 eax, 0x803000
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_12 = { 7508 83c8ff e9???????? 8b839f830000 }
            // n = 4, score = 500
            //   7508                 | jne                 0xa
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     
            //   8b839f830000         | mov                 eax, dword ptr [ebx + 0x839f]

        $sequence_13 = { 53 68000000a0 6a03 53 }
            // n = 4, score = 500
            //   53                   | push                ebx
            //   68000000a0           | push                0xa0000000
            //   6a03                 | push                3
            //   53                   | push                ebx

        $sequence_14 = { 5b c3 55 8bec 833d????????00 53 56 }
            // n = 7, score = 500
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   833d????????00       |                     
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_15 = { 55 56 57 6880020000 }
            // n = 4, score = 500
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi
            //   6880020000           | push                0x280

        $sequence_16 = { 75dd 57 e8???????? 59 }
            // n = 4, score = 500
            //   75dd                 | jne                 0xffffffdf
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_17 = { e8???????? 59 eb57 53 }
            // n = 4, score = 400
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   eb57                 | jmp                 0x59
            //   53                   | push                ebx

        $sequence_18 = { 0245fd 3245fe 8a4dff d2c8 }
            // n = 4, score = 400
            //   0245fd               | add                 al, byte ptr [ebp - 3]
            //   3245fe               | xor                 al, byte ptr [ebp - 2]
            //   8a4dff               | mov                 cl, byte ptr [ebp - 1]
            //   d2c8                 | ror                 al, cl

        $sequence_19 = { 85f6 7409 56 e8???????? 83c404 8bc3 5d }
            // n = 7, score = 400
            //   85f6                 | test                esi, esi
            //   7409                 | je                  0xb
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bc3                 | mov                 eax, ebx
            //   5d                   | pop                 ebp

        $sequence_20 = { 50 e8???????? 59 8b4e2c }
            // n = 4, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b4e2c               | mov                 ecx, dword ptr [esi + 0x2c]

        $sequence_21 = { 016c242c 8b44242c 5f 5e 5d }
            // n = 5, score = 400
            //   016c242c             | add                 dword ptr [esp + 0x2c], ebp
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_22 = { e8???????? 8b4d18 2bf7 56 03fb }
            // n = 5, score = 300
            //   e8????????           |                     
            //   8b4d18               | mov                 ecx, dword ptr [ebp + 0x18]
            //   2bf7                 | sub                 esi, edi
            //   56                   | push                esi
            //   03fb                 | add                 edi, ebx

        $sequence_23 = { 5e 8975f8 7417 c14dfc0d 0fbe340e 0175fc 8b75f8 }
            // n = 7, score = 300
            //   5e                   | pop                 esi
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   7417                 | je                  0x19
            //   c14dfc0d             | ror                 dword ptr [ebp - 4], 0xd
            //   0fbe340e             | movsx               esi, byte ptr [esi + ecx]
            //   0175fc               | add                 dword ptr [ebp - 4], esi
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]

        $sequence_24 = { 7202 8b00 6a04 8d4e34 51 6a04 53 }
            // n = 7, score = 300
            //   7202                 | jb                  4
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   6a04                 | push                4
            //   8d4e34               | lea                 ecx, [esi + 0x34]
            //   51                   | push                ecx
            //   6a04                 | push                4
            //   53                   | push                ebx

        $sequence_25 = { e8???????? 8d85c8feffff e8???????? 8d8590feffff 50 e8???????? 8bf0 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8d85c8feffff         | lea                 eax, [ebp - 0x138]
            //   e8????????           |                     
            //   8d8590feffff         | lea                 eax, [ebp - 0x170]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_26 = { 6a00 53 e8???????? 83c408 85c0 74d0 8bc3 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   74d0                 | je                  0xffffffd2
            //   8bc3                 | mov                 eax, ebx

        $sequence_27 = { 59 ff431c 66c74310d401 8b0d???????? }
            // n = 4, score = 200
            //   59                   | pop                 ecx
            //   ff431c               | inc                 dword ptr [ebx + 0x1c]
            //   66c74310d401         | mov                 word ptr [ebx + 0x10], 0x1d4
            //   8b0d????????         |                     

        $sequence_28 = { 6a00 53 e8???????? 83c40c 33d2 8bc3 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   33d2                 | xor                 edx, edx
            //   8bc3                 | mov                 eax, ebx

    condition:
        7 of them and filesize < 2220032
}