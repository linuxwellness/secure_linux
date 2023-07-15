rule win_sysscan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sysscan"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
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
        $sequence_0 = { c745a0ffffffff e9???????? 8b55e4 8b7a38 0fb64a06 894db8 c7431c028bc761 }
            // n = 7, score = 100
            //   c745a0ffffffff       | mov                 dword ptr [ebp - 0x60], 0xffffffff
            //   e9????????           |                     
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   8b7a38               | mov                 edi, dword ptr [edx + 0x38]
            //   0fb64a06             | movzx               ecx, byte ptr [edx + 6]
            //   894db8               | mov                 dword ptr [ebp - 0x48], ecx
            //   c7431c028bc761       | mov                 dword ptr [ebx + 0x1c], 0x61c78b02

        $sequence_1 = { e9???????? 8a8d20ffffff 8b03 3a08 740e 8b5514 c7022a000000 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8a8d20ffffff         | mov                 cl, byte ptr [ebp - 0xe0]
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   3a08                 | cmp                 cl, byte ptr [eax]
            //   740e                 | je                  0x10
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
            //   c7022a000000         | mov                 dword ptr [edx], 0x2a

        $sequence_2 = { eb10 c744240c0471c761 c7442408ecd80000 c7442404567fc761 c704240b000000 e8???????? b80b000000 }
            // n = 7, score = 100
            //   eb10                 | jmp                 0x12
            //   c744240c0471c761     | mov                 dword ptr [esp + 0xc], 0x61c77104
            //   c7442408ecd80000     | mov                 dword ptr [esp + 8], 0xd8ec
            //   c7442404567fc761     | mov                 dword ptr [esp + 4], 0x61c77f56
            //   c704240b000000       | mov                 dword ptr [esp], 0xb
            //   e8????????           |                     
            //   b80b000000           | mov                 eax, 0xb

        $sequence_3 = { 81c21c200000 89d1 81e1ff0f0000 894dc8 8b7304 c745cc00000000 f7c600040000 }
            // n = 7, score = 100
            //   81c21c200000         | add                 edx, 0x201c
            //   89d1                 | mov                 ecx, edx
            //   81e1ff0f0000         | and                 ecx, 0xfff
            //   894dc8               | mov                 dword ptr [ebp - 0x38], ecx
            //   8b7304               | mov                 esi, dword ptr [ebx + 4]
            //   c745cc00000000       | mov                 dword ptr [ebp - 0x34], 0
            //   f7c600040000         | test                esi, 0x400

        $sequence_4 = { c7432000000000 c7430c00000000 891c24 e8???????? 31c0 83c414 5b }
            // n = 7, score = 100
            //   c7432000000000       | mov                 dword ptr [ebx + 0x20], 0
            //   c7430c00000000       | mov                 dword ptr [ebx + 0xc], 0
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   31c0                 | xor                 eax, eax
            //   83c414               | add                 esp, 0x14
            //   5b                   | pop                 ebx

        $sequence_5 = { e2e0 e2e1 e2e2 e2e3 e2e4 e2e5 e2e6 }
            // n = 7, score = 100
            //   e2e0                 | loop                0xffffffe2
            //   e2e1                 | loop                0xffffffe3
            //   e2e2                 | loop                0xffffffe4
            //   e2e3                 | loop                0xffffffe5
            //   e2e4                 | loop                0xffffffe6
            //   e2e5                 | loop                0xffffffe7
            //   e2e6                 | loop                0xffffffe8

        $sequence_6 = { eb13 0fb78566ffffff 3945d8 0f9dc0 f7d8 21c7 eb1a }
            // n = 7, score = 100
            //   eb13                 | jmp                 0x15
            //   0fb78566ffffff       | movzx               eax, word ptr [ebp - 0x9a]
            //   3945d8               | cmp                 dword ptr [ebp - 0x28], eax
            //   0f9dc0               | setge               al
            //   f7d8                 | neg                 eax
            //   21c7                 | and                 edi, eax
            //   eb1a                 | jmp                 0x1c

        $sequence_7 = { eb40 c645dc05 eb3a c645dc03 eb34 c645dc06 eb2e }
            // n = 7, score = 100
            //   eb40                 | jmp                 0x42
            //   c645dc05             | mov                 byte ptr [ebp - 0x24], 5
            //   eb3a                 | jmp                 0x3c
            //   c645dc03             | mov                 byte ptr [ebp - 0x24], 3
            //   eb34                 | jmp                 0x36
            //   c645dc06             | mov                 byte ptr [ebp - 0x24], 6
            //   eb2e                 | jmp                 0x30

        $sequence_8 = { eb21 8b5628 668955e0 8d4e26 8d55b4 891424 ba01000000 }
            // n = 7, score = 100
            //   eb21                 | jmp                 0x23
            //   8b5628               | mov                 edx, dword ptr [esi + 0x28]
            //   668955e0             | mov                 word ptr [ebp - 0x20], dx
            //   8d4e26               | lea                 ecx, [esi + 0x26]
            //   8d55b4               | lea                 edx, [ebp - 0x4c]
            //   891424               | mov                 dword ptr [esp], edx
            //   ba01000000           | mov                 edx, 1

        $sequence_9 = { ff45e4 8b55e0 3955e4 7ca8 8b75a4 893c24 31c9 }
            // n = 7, score = 100
            //   ff45e4               | inc                 dword ptr [ebp - 0x1c]
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   3955e4               | cmp                 dword ptr [ebp - 0x1c], edx
            //   7ca8                 | jl                  0xffffffaa
            //   8b75a4               | mov                 esi, dword ptr [ebp - 0x5c]
            //   893c24               | mov                 dword ptr [esp], edi
            //   31c9                 | xor                 ecx, ecx

    condition:
        7 of them and filesize < 10141696
}