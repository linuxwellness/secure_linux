rule win_glasses_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.glasses."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glasses"
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
        $sequence_0 = { eb06 807d0b00 7516 8b4d0c 8b01 8b5014 68???????? }
            // n = 7, score = 100
            //   eb06                 | jmp                 8
            //   807d0b00             | cmp                 byte ptr [ebp + 0xb], 0
            //   7516                 | jne                 0x18
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   8b5014               | mov                 edx, dword ptr [eax + 0x14]
            //   68????????           |                     

        $sequence_1 = { e9???????? 8d8d70faffff e9???????? 8b542408 8d420c 8b8aa8efffff 33c8 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d8d70faffff         | lea                 ecx, [ebp - 0x590]
            //   e9????????           |                     
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   8d420c               | lea                 eax, [edx + 0xc]
            //   8b8aa8efffff         | mov                 ecx, dword ptr [edx - 0x1058]
            //   33c8                 | xor                 ecx, eax

        $sequence_2 = { 8d9508ffffff 52 68???????? 8bce e8???????? 8d8d08ffffff e8???????? }
            // n = 7, score = 100
            //   8d9508ffffff         | lea                 edx, [ebp - 0xf8]
            //   52                   | push                edx
            //   68????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8d8d08ffffff         | lea                 ecx, [ebp - 0xf8]
            //   e8????????           |                     

        $sequence_3 = { e8???????? 83c404 898578ffffff 3bc3 7412 8d0cb500000000 51 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   898578ffffff         | mov                 dword ptr [ebp - 0x88], eax
            //   3bc3                 | cmp                 eax, ebx
            //   7412                 | je                  0x14
            //   8d0cb500000000       | lea                 ecx, [esi*4]
            //   51                   | push                ecx

        $sequence_4 = { e8???????? 8b8dd0fbffff 8b95ccfbffff 50 51 52 8d8d20feffff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b8dd0fbffff         | mov                 ecx, dword ptr [ebp - 0x430]
            //   8b95ccfbffff         | mov                 edx, dword ptr [ebp - 0x434]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   52                   | push                edx
            //   8d8d20feffff         | lea                 ecx, [ebp - 0x1e0]

        $sequence_5 = { 8d8558ffffff 50 8bce c645fc01 e8???????? 8d4d88 e8???????? }
            // n = 7, score = 100
            //   8d8558ffffff         | lea                 eax, [ebp - 0xa8]
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   8d4d88               | lea                 ecx, [ebp - 0x78]
            //   e8????????           |                     

        $sequence_6 = { e8???????? 8d7007 c1ee03 85f6 0f8499000000 90 8b4308 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d7007               | lea                 esi, [eax + 7]
            //   c1ee03               | shr                 esi, 3
            //   85f6                 | test                esi, esi
            //   0f8499000000         | je                  0x9f
            //   90                   | nop                 
            //   8b4308               | mov                 eax, dword ptr [ebx + 8]

        $sequence_7 = { f7d6 c745fcffffffff 8d4de4 e8???????? 23f7 740a 8b16 }
            // n = 7, score = 100
            //   f7d6                 | not                 esi
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   e8????????           |                     
            //   23f7                 | and                 esi, edi
            //   740a                 | je                  0xc
            //   8b16                 | mov                 edx, dword ptr [esi]

        $sequence_8 = { e8???????? 8b07 8b5014 68???????? 8bcf ffd2 32c0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   8b5014               | mov                 edx, dword ptr [eax + 0x14]
            //   68????????           |                     
            //   8bcf                 | mov                 ecx, edi
            //   ffd2                 | call                edx
            //   32c0                 | xor                 al, al

        $sequence_9 = { e8???????? 8b4d14 c6460c01 8a17 88560d 53 81c684040000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   c6460c01             | mov                 byte ptr [esi + 0xc], 1
            //   8a17                 | mov                 dl, byte ptr [edi]
            //   88560d               | mov                 byte ptr [esi + 0xd], dl
            //   53                   | push                ebx
            //   81c684040000         | add                 esi, 0x484

    condition:
        7 of them and filesize < 4177920
}