rule win_purplewave_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.purplewave."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.purplewave"
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
        $sequence_0 = { 56 8b750c 40 8902 57 8b7e24 8d4710 }
            // n = 7, score = 400
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   40                   | inc                 eax
            //   8902                 | mov                 dword ptr [edx], eax
            //   57                   | push                edi
            //   8b7e24               | mov                 edi, dword ptr [esi + 0x24]
            //   8d4710               | lea                 eax, [edi + 0x10]

        $sequence_1 = { 56 8bcb e8???????? 83c34c 83c64c 895de8 3bf7 }
            // n = 7, score = 400
            //   56                   | push                esi
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   83c34c               | add                 ebx, 0x4c
            //   83c64c               | add                 esi, 0x4c
            //   895de8               | mov                 dword ptr [ebp - 0x18], ebx
            //   3bf7                 | cmp                 esi, edi

        $sequence_2 = { e8???????? 8b5640 8b7644 8b4df4 890f 8b4df8 894f04 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8b5640               | mov                 edx, dword ptr [esi + 0x40]
            //   8b7644               | mov                 esi, dword ptr [esi + 0x44]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   890f                 | mov                 dword ptr [edi], ecx
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   894f04               | mov                 dword ptr [edi + 4], ecx

        $sequence_3 = { 8b7dfc 8b37 8b4708 b984000000 2bc6 99 }
            // n = 6, score = 400
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   8b37                 | mov                 esi, dword ptr [edi]
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   b984000000           | mov                 ecx, 0x84
            //   2bc6                 | sub                 eax, esi
            //   99                   | cdq                 

        $sequence_4 = { 8d8c2498010000 e8???????? 83c418 8d8c2468010000 e8???????? 6a0f }
            // n = 6, score = 400
            //   8d8c2498010000       | lea                 ecx, [esp + 0x198]
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   8d8c2468010000       | lea                 ecx, [esp + 0x168]
            //   e8????????           |                     
            //   6a0f                 | push                0xf

        $sequence_5 = { 33c8 e8???????? b8???????? e9???????? 8d4d08 e9???????? 8b8528ffffff }
            // n = 7, score = 400
            //   33c8                 | xor                 ecx, eax
            //   e8????????           |                     
            //   b8????????           |                     
            //   e9????????           |                     
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   e9????????           |                     
            //   8b8528ffffff         | mov                 eax, dword ptr [ebp - 0xd8]

        $sequence_6 = { 6a00 57 e8???????? 6a0f 59 51 8d7718 }
            // n = 7, score = 400
            //   6a00                 | push                0
            //   57                   | push                edi
            //   e8????????           |                     
            //   6a0f                 | push                0xf
            //   59                   | pop                 ecx
            //   51                   | push                ecx
            //   8d7718               | lea                 esi, [edi + 0x18]

        $sequence_7 = { 8a4430ff 8b750c 8802 8ac1 8845e3 eb05 8ac3 }
            // n = 7, score = 400
            //   8a4430ff             | mov                 al, byte ptr [eax + esi - 1]
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8802                 | mov                 byte ptr [edx], al
            //   8ac1                 | mov                 al, cl
            //   8845e3               | mov                 byte ptr [ebp - 0x1d], al
            //   eb05                 | jmp                 7
            //   8ac3                 | mov                 al, bl

        $sequence_8 = { 895e3c 8bc6 895e40 895e44 895e48 895e4c 895e50 }
            // n = 7, score = 400
            //   895e3c               | mov                 dword ptr [esi + 0x3c], ebx
            //   8bc6                 | mov                 eax, esi
            //   895e40               | mov                 dword ptr [esi + 0x40], ebx
            //   895e44               | mov                 dword ptr [esi + 0x44], ebx
            //   895e48               | mov                 dword ptr [esi + 0x48], ebx
            //   895e4c               | mov                 dword ptr [esi + 0x4c], ebx
            //   895e50               | mov                 dword ptr [esi + 0x50], ebx

        $sequence_9 = { 51 8d4d9c e8???????? c745fc01000000 8d4d9c c745ec12000000 e8???????? }
            // n = 7, score = 400
            //   51                   | push                ecx
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]
            //   e8????????           |                     
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]
            //   c745ec12000000       | mov                 dword ptr [ebp - 0x14], 0x12
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1400832
}