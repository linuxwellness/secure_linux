rule osx_pirrit_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.pirrit"
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
        $sequence_0 = { 5b 5d ff25???????? 8b4338 }
            // n = 4, score = 100
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   ff25????????         |                     
            //   8b4338               | mov                 eax, dword ptr [ebx + 0x38]

        $sequence_1 = { 48 8d0d894b0000 48 8b35???????? }
            // n = 4, score = 100
            //   48                   | dec                 eax
            //   8d0d894b0000         | lea                 ecx, [0x4b89]
            //   48                   | dec                 eax
            //   8b35????????         |                     

        $sequence_2 = { c705????????00000000 48 8d05d6270000 48 8905???????? 48 }
            // n = 6, score = 100
            //   c705????????00000000     |     
            //   48                   | dec                 eax
            //   8d05d6270000         | lea                 eax, [0x27d6]
            //   48                   | dec                 eax
            //   8905????????         |                     
            //   48                   | dec                 eax

        $sequence_3 = { 89c6 48 8b3d???????? 48 8b35???????? 4c 8b3d???????? }
            // n = 7, score = 100
            //   89c6                 | mov                 esi, eax
            //   48                   | dec                 eax
            //   8b3d????????         |                     
            //   48                   | dec                 eax
            //   8b35????????         |                     
            //   4c                   | dec                 esp
            //   8b3d????????         |                     

        $sequence_4 = { 48 8945d8 b000 e8???????? }
            // n = 4, score = 100
            //   48                   | dec                 eax
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   b000                 | mov                 al, 0
            //   e8????????           |                     

        $sequence_5 = { 48 8b7f08 48 8b15???????? }
            // n = 4, score = 100
            //   48                   | dec                 eax
            //   8b7f08               | mov                 edi, dword ptr [edi + 8]
            //   48                   | dec                 eax
            //   8b15????????         |                     

        $sequence_6 = { 48 8d05bd130000 48 8d0d020e0000 }
            // n = 4, score = 100
            //   48                   | dec                 eax
            //   8d05bd130000         | lea                 eax, [0x13bd]
            //   48                   | dec                 eax
            //   8d0d020e0000         | lea                 ecx, [0xe02]

        $sequence_7 = { 48 8b7dd8 45 84f6 7414 48 8d352f2e0000 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8b7dd8               | mov                 edi, dword ptr [ebp - 0x28]
            //   45                   | inc                 ebp
            //   84f6                 | test                dh, dh
            //   7414                 | je                  0x16
            //   48                   | dec                 eax
            //   8d352f2e0000         | lea                 esi, [0x2e2f]

        $sequence_8 = { 8d059f2c0000 48 8d0db52c0000 48 }
            // n = 4, score = 100
            //   8d059f2c0000         | lea                 eax, [0x2c9f]
            //   48                   | dec                 eax
            //   8d0db52c0000         | lea                 ecx, [0x2cb5]
            //   48                   | dec                 eax

        $sequence_9 = { 0f85e5010000 48 8d3da70b0000 e8???????? 48 }
            // n = 5, score = 100
            //   0f85e5010000         | jne                 0x1eb
            //   48                   | dec                 eax
            //   8d3da70b0000         | lea                 edi, [0xba7]
            //   e8????????           |                     
            //   48                   | dec                 eax

        $sequence_10 = { 56 53 50 49 89fe be01000000 e8???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   53                   | push                ebx
            //   50                   | push                eax
            //   49                   | dec                 ecx
            //   89fe                 | mov                 esi, edi
            //   be01000000           | mov                 esi, 1
            //   e8????????           |                     

        $sequence_11 = { 8d35972e0000 ba02000000 48 89df e8???????? 85c0 }
            // n = 6, score = 100
            //   8d35972e0000         | lea                 esi, [0x2e97]
            //   ba02000000           | mov                 edx, 2
            //   48                   | dec                 eax
            //   89df                 | mov                 edi, ebx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_12 = { 89cf 88853ffeffff e8???????? 8a853ffeffff a801 0f8505000000 e9???????? }
            // n = 7, score = 100
            //   89cf                 | mov                 edi, ecx
            //   88853ffeffff         | mov                 byte ptr [ebp - 0x1c1], al
            //   e8????????           |                     
            //   8a853ffeffff         | mov                 al, byte ptr [ebp - 0x1c1]
            //   a801                 | test                al, 1
            //   0f8505000000         | jne                 0xb
            //   e9????????           |                     

        $sequence_13 = { 48 c705????????00000000 48 8d0546290000 48 8905???????? 48 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   c705????????00000000     |     
            //   48                   | dec                 eax
            //   8d0546290000         | lea                 eax, [0x2946]
            //   48                   | dec                 eax
            //   8905????????         |                     
            //   48                   | dec                 eax

        $sequence_14 = { 48 0f45c8 48 890c24 48 8d35492c0000 }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   0f45c8               | cmovne              ecx, eax
            //   48                   | dec                 eax
            //   890c24               | mov                 dword ptr [esp], ecx
            //   48                   | dec                 eax
            //   8d35492c0000         | lea                 esi, [0x2c49]

        $sequence_15 = { 747f eb1a 48 8d05662e0000 48 8945d0 }
            // n = 6, score = 100
            //   747f                 | je                  0x81
            //   eb1a                 | jmp                 0x1c
            //   48                   | dec                 eax
            //   8d05662e0000         | lea                 eax, [0x2e66]
            //   48                   | dec                 eax
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax

    condition:
        7 of them and filesize < 169600
}