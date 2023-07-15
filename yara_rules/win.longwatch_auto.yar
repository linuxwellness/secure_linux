rule win_longwatch_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.longwatch."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.longwatch"
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
        $sequence_0 = { 03048da00b4300 eb02 8bc7 80782900 }
            // n = 4, score = 200
            //   03048da00b4300       | add                 eax, dword ptr [ecx*4 + 0x430ba0]
            //   eb02                 | jmp                 4
            //   8bc7                 | mov                 eax, edi
            //   80782900             | cmp                 byte ptr [eax + 0x29], 0

        $sequence_1 = { 8bec 53 8b5d08 33c9 57 33c0 8d3c9d2c074300 }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   33c9                 | xor                 ecx, ecx
            //   57                   | push                edi
            //   33c0                 | xor                 eax, eax
            //   8d3c9d2c074300       | lea                 edi, [ebx*4 + 0x43072c]

        $sequence_2 = { 59 59 0304bda00b4300 5f eb05 }
            // n = 5, score = 200
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   0304bda00b4300       | add                 eax, dword ptr [edi*4 + 0x430ba0]
            //   5f                   | pop                 edi
            //   eb05                 | jmp                 7

        $sequence_3 = { eb29 8b55d4 8a07 8b0c95a00b4300 }
            // n = 4, score = 200
            //   eb29                 | jmp                 0x2b
            //   8b55d4               | mov                 edx, dword ptr [ebp - 0x2c]
            //   8a07                 | mov                 al, byte ptr [edi]
            //   8b0c95a00b4300       | mov                 ecx, dword ptr [edx*4 + 0x430ba0]

        $sequence_4 = { 56 33f6 8b86a00b4300 85c0 }
            // n = 4, score = 200
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   8b86a00b4300         | mov                 eax, dword ptr [esi + 0x430ba0]
            //   85c0                 | test                eax, eax

        $sequence_5 = { 8b404c 83b8a800000000 7512 8b04bda00b4300 }
            // n = 4, score = 200
            //   8b404c               | mov                 eax, dword ptr [eax + 0x4c]
            //   83b8a800000000       | cmp                 dword ptr [eax + 0xa8], 0
            //   7512                 | jne                 0x14
            //   8b04bda00b4300       | mov                 eax, dword ptr [edi*4 + 0x430ba0]

        $sequence_6 = { 8bc2 8bca 83e03f c1f906 6bc030 03048da00b4300 eb05 }
            // n = 7, score = 200
            //   8bc2                 | mov                 eax, edx
            //   8bca                 | mov                 ecx, edx
            //   83e03f               | and                 eax, 0x3f
            //   c1f906               | sar                 ecx, 6
            //   6bc030               | imul                eax, eax, 0x30
            //   03048da00b4300       | add                 eax, dword ptr [ecx*4 + 0x430ba0]
            //   eb05                 | jmp                 7

        $sequence_7 = { e8???????? 68???????? 8d442410 c744241078334200 50 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   68????????           |                     
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   c744241078334200     | mov                 dword ptr [esp + 0x10], 0x423378
            //   50                   | push                eax

        $sequence_8 = { 6bc930 53 56 8b0485a00b4300 33db }
            // n = 5, score = 200
            //   6bc930               | imul                ecx, ecx, 0x30
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b0485a00b4300       | mov                 eax, dword ptr [eax*4 + 0x430ba0]
            //   33db                 | xor                 ebx, ebx

        $sequence_9 = { 88852fffffff e8???????? 8d43bf 83f819 7721 }
            // n = 5, score = 200
            //   88852fffffff         | mov                 byte ptr [ebp - 0xd1], al
            //   e8????????           |                     
            //   8d43bf               | lea                 eax, [ebx - 0x41]
            //   83f819               | cmp                 eax, 0x19
            //   7721                 | ja                  0x23

    condition:
        7 of them and filesize < 647168
}