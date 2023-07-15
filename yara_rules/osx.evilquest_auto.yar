rule osx_evilquest_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.evilquest"
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
        $sequence_0 = { 897de0 48 8975d8 48 8955d0 48 c745c800000000 }
            // n = 7, score = 100
            //   897de0               | mov                 dword ptr [ebp - 0x20], edi
            //   48                   | dec                 eax
            //   8975d8               | mov                 dword ptr [ebp - 0x28], esi
            //   48                   | dec                 eax
            //   8955d0               | mov                 dword ptr [ebp - 0x30], edx
            //   48                   | dec                 eax
            //   c745c800000000       | mov                 dword ptr [ebp - 0x38], 0

        $sequence_1 = { 8945f0 48 8b4dd8 48 0faf4dd8 8b45ec 89c2 }
            // n = 7, score = 100
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   48                   | dec                 eax
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   48                   | dec                 eax
            //   0faf4dd8             | imul                ecx, dword ptr [ebp - 0x28]
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   89c2                 | mov                 edx, eax

        $sequence_2 = { 894dd0 4c 89c1 4c 8b45d0 4c 8b4dd0 }
            // n = 7, score = 100
            //   894dd0               | mov                 dword ptr [ebp - 0x30], ecx
            //   4c                   | dec                 esp
            //   89c1                 | mov                 ecx, eax
            //   4c                   | dec                 esp
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   4c                   | dec                 esp
            //   8b4dd0               | mov                 ecx, dword ptr [ebp - 0x30]

        $sequence_3 = { 837dd000 0f8416000000 48 8b7db0 48 8b75e8 e8???????? }
            // n = 7, score = 100
            //   837dd000             | cmp                 dword ptr [ebp - 0x30], 0
            //   0f8416000000         | je                  0x1c
            //   48                   | dec                 eax
            //   8b7db0               | mov                 edi, dword ptr [ebp - 0x50]
            //   48                   | dec                 eax
            //   8b75e8               | mov                 esi, dword ptr [ebp - 0x18]
            //   e8????????           |                     

        $sequence_4 = { 8b4de8 48 8901 48 8b45f0 48 833800 }
            // n = 7, score = 100
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   48                   | dec                 eax
            //   8901                 | mov                 dword ptr [ecx], eax
            //   48                   | dec                 eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   48                   | dec                 eax
            //   833800               | cmp                 dword ptr [eax], 0

        $sequence_5 = { 48 8945d8 48 8b7dd8 e8???????? 48 8b7df0 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   48                   | dec                 eax
            //   8b7dd8               | mov                 edi, dword ptr [ebp - 0x28]
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8b7df0               | mov                 edi, dword ptr [ebp - 0x10]

        $sequence_6 = { 48 8d05c2580000 48 8945f8 e9???????? 48 8d05c1580000 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8d05c2580000         | lea                 eax, [0x58c2]
            //   48                   | dec                 eax
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   e9????????           |                     
            //   48                   | dec                 eax
            //   8d05c1580000         | lea                 eax, [0x58c1]

        $sequence_7 = { 48 89c7 48 898da8feffff 48 89b5a0feffff }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   89c7                 | mov                 edi, eax
            //   48                   | dec                 eax
            //   898da8feffff         | mov                 dword ptr [ebp - 0x158], ecx
            //   48                   | dec                 eax
            //   89b5a0feffff         | mov                 dword ptr [ebp - 0x160], esi

        $sequence_8 = { 48 8b8548ffffff 48 8b10 be???????? e8???????? 48 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8b8548ffffff         | mov                 eax, dword ptr [ebp - 0xb8]
            //   48                   | dec                 eax
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   be????????           |                     
            //   e8????????           |                     
            //   48                   | dec                 eax

        $sequence_9 = { 48 8d3dddde0000 e8???????? 48 8945d0 48 8b7dd0 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8d3dddde0000         | lea                 edi, [0xdedd]
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   48                   | dec                 eax
            //   8b7dd0               | mov                 edi, dword ptr [ebp - 0x30]

    condition:
        7 of them and filesize < 175840
}