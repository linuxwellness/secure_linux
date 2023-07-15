rule win_qakbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-29"
        version = "1"
        description = "Detects win.qakbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.qakbot"
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
        $sequence_0 = { 50 e8???????? 8b06 47 59 }
            // n = 5, score = 11500
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   47                   | inc                 edi
            //   59                   | pop                 ecx

        $sequence_1 = { e9???????? 33c0 7402 ebfa }
            // n = 4, score = 11400
            //   e9????????           |                     
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4
            //   ebfa                 | jmp                 0xfffffffc

        $sequence_2 = { 7402 ebfa 33c0 7402 }
            // n = 4, score = 11200
            //   7402                 | je                  4
            //   ebfa                 | jmp                 0xfffffffc
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_3 = { ebfa eb06 33c0 7402 }
            // n = 4, score = 11200
            //   ebfa                 | jmp                 0xfffffffc
            //   eb06                 | jmp                 8
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_4 = { 740d 8d45fc 6a00 50 e8???????? 59 59 }
            // n = 7, score = 11100
            //   740d                 | je                  0xf
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_5 = { e8???????? 33c9 85c0 0f9fc1 41 }
            // n = 5, score = 11000
            //   e8????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   85c0                 | test                eax, eax
            //   0f9fc1               | setg                cl
            //   41                   | inc                 ecx

        $sequence_6 = { 59 59 6afb e9???????? }
            // n = 4, score = 10900
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   6afb                 | push                -5
            //   e9????????           |                     

        $sequence_7 = { 48 50 8d8534f6ffff 6a00 50 }
            // n = 5, score = 10800
            //   48                   | dec                 eax
            //   50                   | push                eax
            //   8d8534f6ffff         | lea                 eax, [ebp - 0x9cc]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_8 = { 8945fc e8???????? 8bf0 8d45fc 50 e8???????? }
            // n = 6, score = 10400
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_9 = { 8975f8 8975f0 8975f4 e8???????? }
            // n = 4, score = 10300
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   e8????????           |                     

        $sequence_10 = { 5e c9 c3 55 8bec 81ecc4090000 }
            // n = 6, score = 10200
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ecc4090000         | sub                 esp, 0x9c4

        $sequence_11 = { c644301c00 ff465c 8b465c 83f838 7cf0 8a461b }
            // n = 6, score = 10100
            //   c644301c00           | mov                 byte ptr [eax + esi + 0x1c], 0
            //   ff465c               | inc                 dword ptr [esi + 0x5c]
            //   8b465c               | mov                 eax, dword ptr [esi + 0x5c]
            //   83f838               | cmp                 eax, 0x38
            //   7cf0                 | jl                  0xfffffff2
            //   8a461b               | mov                 al, byte ptr [esi + 0x1b]

        $sequence_12 = { eb0b c644301c00 ff465c 8b465c 83f840 7cf0 }
            // n = 6, score = 10100
            //   eb0b                 | jmp                 0xd
            //   c644301c00           | mov                 byte ptr [eax + esi + 0x1c], 0
            //   ff465c               | inc                 dword ptr [esi + 0x5c]
            //   8b465c               | mov                 eax, dword ptr [esi + 0x5c]
            //   83f840               | cmp                 eax, 0x40
            //   7cf0                 | jl                  0xfffffff2

        $sequence_13 = { 85c0 750a 33c0 7402 }
            // n = 4, score = 10100
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_14 = { ff465c 837e5c38 7cef eb10 c644301c00 ff465c 8b465c }
            // n = 7, score = 10100
            //   ff465c               | inc                 dword ptr [esi + 0x5c]
            //   837e5c38             | cmp                 dword ptr [esi + 0x5c], 0x38
            //   7cef                 | jl                  0xfffffff1
            //   eb10                 | jmp                 0x12
            //   c644301c00           | mov                 byte ptr [eax + esi + 0x1c], 0
            //   ff465c               | inc                 dword ptr [esi + 0x5c]
            //   8b465c               | mov                 eax, dword ptr [esi + 0x5c]

        $sequence_15 = { 8d45f8 6aff 50 e8???????? }
            // n = 4, score = 10000
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_16 = { e8???????? 83c410 33c0 7402 }
            // n = 4, score = 9800
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_17 = { 7507 c7466401000000 83f840 7507 }
            // n = 4, score = 9500
            //   7507                 | jne                 9
            //   c7466401000000       | mov                 dword ptr [esi + 0x64], 1
            //   83f840               | cmp                 eax, 0x40
            //   7507                 | jne                 9

        $sequence_18 = { 7402 ebfa e9???????? 6a00 }
            // n = 4, score = 9000
            //   7402                 | je                  4
            //   ebfa                 | jmp                 0xfffffffc
            //   e9????????           |                     
            //   6a00                 | push                0

        $sequence_19 = { c7466001000000 33c0 40 5e }
            // n = 4, score = 9000
            //   c7466001000000       | mov                 dword ptr [esi + 0x60], 1
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   5e                   | pop                 esi

        $sequence_20 = { 6afe 8d45f4 50 e8???????? }
            // n = 4, score = 8500
            //   6afe                 | push                -2
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_21 = { e8???????? 33d2 6a30 59 f7f1 }
            // n = 5, score = 8400
            //   e8????????           |                     
            //   33d2                 | xor                 edx, edx
            //   6a30                 | push                0x30
            //   59                   | pop                 ecx
            //   f7f1                 | div                 ecx

        $sequence_22 = { 7402 ebfa eb0d 33c0 }
            // n = 4, score = 8400
            //   7402                 | je                  4
            //   ebfa                 | jmp                 0xfffffffc
            //   eb0d                 | jmp                 0xf
            //   33c0                 | xor                 eax, eax

        $sequence_23 = { e8???????? 33c0 c3 55 8bec 51 51 }
            // n = 7, score = 6000
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   51                   | push                ecx

        $sequence_24 = { 50 ff5508 8bf0 59 }
            // n = 4, score = 4900
            //   50                   | push                eax
            //   ff5508               | call                dword ptr [ebp + 8]
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx

        $sequence_25 = { 6a00 58 0f95c0 40 50 }
            // n = 5, score = 4500
            //   6a00                 | push                0
            //   58                   | pop                 eax
            //   0f95c0               | setne               al
            //   40                   | inc                 eax
            //   50                   | push                eax

        $sequence_26 = { 57 ff15???????? 33c0 85f6 0f94c0 }
            // n = 5, score = 4100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   85f6                 | test                esi, esi
            //   0f94c0               | sete                al

        $sequence_27 = { 85c0 750c 57 ff15???????? 6afe 58 }
            // n = 6, score = 3900
            //   85c0                 | test                eax, eax
            //   750c                 | jne                 0xe
            //   57                   | push                edi
            //   ff15????????         |                     
            //   6afe                 | push                -2
            //   58                   | pop                 eax

        $sequence_28 = { c3 33c9 3d80000000 0f94c1 }
            // n = 4, score = 3900
            //   c3                   | ret                 
            //   33c9                 | xor                 ecx, ecx
            //   3d80000000           | cmp                 eax, 0x80
            //   0f94c1               | sete                cl

        $sequence_29 = { 6a02 ff15???????? 8bf8 83c8ff 3bf8 }
            // n = 5, score = 3900
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   83c8ff               | or                  eax, 0xffffffff
            //   3bf8                 | cmp                 edi, eax

        $sequence_30 = { ff750c 8d85d8feffff 50 ff5508 }
            // n = 4, score = 3500
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d85d8feffff         | lea                 eax, [ebp - 0x128]
            //   50                   | push                eax
            //   ff5508               | call                dword ptr [ebp + 8]

        $sequence_31 = { 00e9 8b55e4 880c1a 8a4df3 }
            // n = 4, score = 100
            //   00e9                 | add                 cl, ch
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   880c1a               | mov                 byte ptr [edx + ebx], cl
            //   8a4df3               | mov                 cl, byte ptr [ebp - 0xd]

        $sequence_32 = { 01c1 894c2404 8b442404 8d65fc }
            // n = 4, score = 100
            //   01c1                 | add                 ecx, eax
            //   894c2404             | mov                 dword ptr [esp + 4], ecx
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   8d65fc               | lea                 esp, [ebp - 4]

        $sequence_33 = { 00ca 66897c2446 31f6 8974244c }
            // n = 4, score = 100
            //   00ca                 | add                 dl, cl
            //   66897c2446           | mov                 word ptr [esp + 0x46], di
            //   31f6                 | xor                 esi, esi
            //   8974244c             | mov                 dword ptr [esp + 0x4c], esi

        $sequence_34 = { 01c1 894c2430 e9???????? 55 }
            // n = 4, score = 100
            //   01c1                 | add                 ecx, eax
            //   894c2430             | mov                 dword ptr [esp + 0x30], ecx
            //   e9????????           |                     
            //   55                   | push                ebp

        $sequence_35 = { 01c1 21d1 8a442465 f6642465 }
            // n = 4, score = 100
            //   01c1                 | add                 ecx, eax
            //   21d1                 | and                 ecx, edx
            //   8a442465             | mov                 al, byte ptr [esp + 0x65]
            //   f6642465             | mul                 byte ptr [esp + 0x65]

        $sequence_36 = { 01c1 8b442448 01c8 8944243c }
            // n = 4, score = 100
            //   01c1                 | add                 ecx, eax
            //   8b442448             | mov                 eax, dword ptr [esp + 0x48]
            //   01c8                 | add                 eax, ecx
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax

        $sequence_37 = { 01c1 81e1ffff0000 83c101 8b442474 }
            // n = 4, score = 100
            //   01c1                 | add                 ecx, eax
            //   81e1ffff0000         | and                 ecx, 0xffff
            //   83c101               | add                 ecx, 1
            //   8b442474             | mov                 eax, dword ptr [esp + 0x74]

        $sequence_38 = { 00e9 884c0451 83c001 39d0 }
            // n = 4, score = 100
            //   00e9                 | add                 cl, ch
            //   884c0451             | mov                 byte ptr [esp + eax + 0x51], cl
            //   83c001               | add                 eax, 1
            //   39d0                 | cmp                 eax, edx

    condition:
        7 of them and filesize < 1168384
}