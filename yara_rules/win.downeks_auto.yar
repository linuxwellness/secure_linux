rule win_downeks_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.downeks."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.downeks"
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
        $sequence_0 = { e8???????? 8b7708 83fe01 7dad 8b4dfc 5e 33cd }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b7708               | mov                 esi, dword ptr [edi + 8]
            //   83fe01               | cmp                 esi, 1
            //   7dad                 | jge                 0xffffffaf
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   5e                   | pop                 esi
            //   33cd                 | xor                 ecx, ebp

        $sequence_1 = { 85c0 0f98c1 8bc1 85c0 74bd 8b4b60 8b15???????? }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   0f98c1               | sets                cl
            //   8bc1                 | mov                 eax, ecx
            //   85c0                 | test                eax, eax
            //   74bd                 | je                  0xffffffbf
            //   8b4b60               | mov                 ecx, dword ptr [ebx + 0x60]
            //   8b15????????         |                     

        $sequence_2 = { e8???????? 8bf0 83c40c 85f6 752d 8d4612 eb21 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c40c               | add                 esp, 0xc
            //   85f6                 | test                esi, esi
            //   752d                 | jne                 0x2f
            //   8d4612               | lea                 eax, [esi + 0x12]
            //   eb21                 | jmp                 0x23

        $sequence_3 = { 6a01 6a00 56 50 ff15???????? 8b8da8fdffff 51 }
            // n = 7, score = 200
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   56                   | push                esi
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b8da8fdffff         | mov                 ecx, dword ptr [ebp - 0x258]
            //   51                   | push                ecx

        $sequence_4 = { e8???????? 85db 0f8ead000000 8b955cffffff 8bbd58ffffff 8d4bff 2bd7 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   85db                 | test                ebx, ebx
            //   0f8ead000000         | jle                 0xb3
            //   8b955cffffff         | mov                 edx, dword ptr [ebp - 0xa4]
            //   8bbd58ffffff         | mov                 edi, dword ptr [ebp - 0xa8]
            //   8d4bff               | lea                 ecx, [ebx - 1]
            //   2bd7                 | sub                 edx, edi

        $sequence_5 = { 85f6 7508 b81b000000 5e 5d c3 8d5001 }
            // n = 7, score = 200
            //   85f6                 | test                esi, esi
            //   7508                 | jne                 0xa
            //   b81b000000           | mov                 eax, 0x1b
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8d5001               | lea                 edx, [eax + 1]

        $sequence_6 = { 8bc1 83f82c 7435 83f85d 745a 837f1800 7417 }
            // n = 7, score = 200
            //   8bc1                 | mov                 eax, ecx
            //   83f82c               | cmp                 eax, 0x2c
            //   7435                 | je                  0x37
            //   83f85d               | cmp                 eax, 0x5d
            //   745a                 | je                  0x5c
            //   837f1800             | cmp                 dword ptr [edi + 0x18], 0
            //   7417                 | je                  0x19

        $sequence_7 = { e8???????? 50 8b852cffffff 56 6854150804 50 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   50                   | push                eax
            //   8b852cffffff         | mov                 eax, dword ptr [ebp - 0xd4]
            //   56                   | push                esi
            //   6854150804           | push                0x4081554
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_8 = { b927000000 8db588fdffff 50 f3a5 e8???????? 83c404 8bfc }
            // n = 7, score = 200
            //   b927000000           | mov                 ecx, 0x27
            //   8db588fdffff         | lea                 esi, [ebp - 0x278]
            //   50                   | push                eax
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bfc                 | mov                 edi, esp

        $sequence_9 = { c1e91f 33ff 03ca 7435 33db 8d55c0 52 }
            // n = 7, score = 200
            //   c1e91f               | shr                 ecx, 0x1f
            //   33ff                 | xor                 edi, edi
            //   03ca                 | add                 ecx, edx
            //   7435                 | je                  0x37
            //   33db                 | xor                 ebx, ebx
            //   8d55c0               | lea                 edx, [ebp - 0x40]
            //   52                   | push                edx

    condition:
        7 of them and filesize < 1318912
}