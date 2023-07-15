rule win_formbook_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.formbook."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.formbook"
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
        $sequence_0 = { 8b55fc 53 52 56 e8???????? 8b4508 50 }
            // n = 7, score = 2200
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   53                   | push                ebx
            //   52                   | push                edx
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax

        $sequence_1 = { 51 e8???????? 8b5614 52 56 e8???????? }
            // n = 6, score = 2200
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b5614               | mov                 edx, dword ptr [esi + 0x14]
            //   52                   | push                edx
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_2 = { 57 33c9 bf00010000 90 8bc1 c1e018 be08000000 }
            // n = 7, score = 2200
            //   57                   | push                edi
            //   33c9                 | xor                 ecx, ecx
            //   bf00010000           | mov                 edi, 0x100
            //   90                   | nop                 
            //   8bc1                 | mov                 eax, ecx
            //   c1e018               | shl                 eax, 0x18
            //   be08000000           | mov                 esi, 8

        $sequence_3 = { 8b450c 8b08 8b5508 83e914 51 52 e8???????? }
            // n = 7, score = 2200
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   83e914               | sub                 ecx, 0x14
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_4 = { 8b0b 51 57 e8???????? 83c408 5b 5f }
            // n = 7, score = 2200
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   51                   | push                ecx
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi

        $sequence_5 = { be08000000 8d9b00000000 85c0 7909 03c0 35b71dc104 eb02 }
            // n = 7, score = 2200
            //   be08000000           | mov                 esi, 8
            //   8d9b00000000         | lea                 ebx, [ebx]
            //   85c0                 | test                eax, eax
            //   7909                 | jns                 0xb
            //   03c0                 | add                 eax, eax
            //   35b71dc104           | xor                 eax, 0x4c11db7
            //   eb02                 | jmp                 4

        $sequence_6 = { e8???????? 8b4f04 56 51 e8???????? 33c0 83c410 }
            // n = 7, score = 2200
            //   e8????????           |                     
            //   8b4f04               | mov                 ecx, dword ptr [edi + 4]
            //   56                   | push                esi
            //   51                   | push                ecx
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   83c410               | add                 esp, 0x10

        $sequence_7 = { 897dfc 83ff14 0f8cf2feffff bf14000000 c1c605 8bda 33d9 }
            // n = 7, score = 2200
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   83ff14               | cmp                 edi, 0x14
            //   0f8cf2feffff         | jl                  0xfffffef8
            //   bf14000000           | mov                 edi, 0x14
            //   c1c605               | rol                 esi, 5
            //   8bda                 | mov                 ebx, edx
            //   33d9                 | xor                 ebx, ecx

        $sequence_8 = { e8???????? 83c428 8906 85c0 75a8 5f 33c0 }
            // n = 7, score = 2200
            //   e8????????           |                     
            //   83c428               | add                 esp, 0x28
            //   8906                 | mov                 dword ptr [esi], eax
            //   85c0                 | test                eax, eax
            //   75a8                 | jne                 0xffffffaa
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { e8???????? 83c40c 85c0 7510 47 83c318 3b7e0c }
            // n = 7, score = 2200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   7510                 | jne                 0x12
            //   47                   | inc                 edi
            //   83c318               | add                 ebx, 0x18
            //   3b7e0c               | cmp                 edi, dword ptr [esi + 0xc]

    condition:
        7 of them and filesize < 371712
}