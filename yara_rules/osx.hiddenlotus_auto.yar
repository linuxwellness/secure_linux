rule osx_hiddenlotus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.hiddenlotus"
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
        $sequence_0 = { be???????? 48 89da e8???????? 49 }
            // n = 5, score = 100
            //   be????????           |                     
            //   48                   | dec                 eax
            //   89da                 | mov                 edx, ebx
            //   e8????????           |                     
            //   49                   | dec                 ecx

        $sequence_1 = { 48 8dbd18eeffff 48 8db510eeffff e8???????? 48 8d35b7840000 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8dbd18eeffff         | lea                 edi, [ebp - 0x11e8]
            //   48                   | dec                 eax
            //   8db510eeffff         | lea                 esi, [ebp - 0x11f0]
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8d35b7840000         | lea                 esi, [0x84b7]

        $sequence_2 = { 48 ffc0 48 83f804 75dc }
            // n = 5, score = 100
            //   48                   | dec                 eax
            //   ffc0                 | inc                 eax
            //   48                   | dec                 eax
            //   83f804               | cmp                 eax, 4
            //   75dc                 | jne                 0xffffffde

        $sequence_3 = { 85c9 0f8f2ff8ffff 48 8db560f6ffff e8???????? e9???????? b9ffffffff }
            // n = 7, score = 100
            //   85c9                 | test                ecx, ecx
            //   0f8f2ff8ffff         | jg                  0xfffff835
            //   48                   | dec                 eax
            //   8db560f6ffff         | lea                 esi, [ebp - 0x9a0]
            //   e8????????           |                     
            //   e9????????           |                     
            //   b9ffffffff           | mov                 ecx, 0xffffffff

        $sequence_4 = { 8b8558ffffff 48 8d78e8 48 3b3d???????? 0f85ee060000 }
            // n = 6, score = 100
            //   8b8558ffffff         | mov                 eax, dword ptr [ebp - 0xa8]
            //   48                   | dec                 eax
            //   8d78e8               | lea                 edi, [eax - 0x18]
            //   48                   | dec                 eax
            //   3b3d????????         |                     
            //   0f85ee060000         | jne                 0x6f4

        $sequence_5 = { 48 8d75d0 e8???????? 48 8b8530eeffff 48 8d78e8 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8d75d0               | lea                 esi, [ebp - 0x30]
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8b8530eeffff         | mov                 eax, dword ptr [ebp - 0x11d0]
            //   48                   | dec                 eax
            //   8d78e8               | lea                 edi, [eax - 0x18]

        $sequence_6 = { 4c 8dad30f0ffff 4c 89ef }
            // n = 4, score = 100
            //   4c                   | dec                 esp
            //   8dad30f0ffff         | lea                 ebp, [ebp - 0xfd0]
            //   4c                   | dec                 esp
            //   89ef                 | mov                 edi, ebp

        $sequence_7 = { 4c 89a578ffffff 48 8d7d90 4c 89fe e8???????? }
            // n = 7, score = 100
            //   4c                   | dec                 esp
            //   89a578ffffff         | mov                 dword ptr [ebp - 0x88], esp
            //   48                   | dec                 eax
            //   8d7d90               | lea                 edi, [ebp - 0x70]
            //   4c                   | dec                 esp
            //   89fe                 | mov                 esi, edi
            //   e8????????           |                     

        $sequence_8 = { 48 81fb004e7253 7c10 31ff e8???????? 48 39c3 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   81fb004e7253         | cmp                 ebx, 0x53724e00
            //   7c10                 | jl                  0x12
            //   31ff                 | xor                 edi, edi
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   39c3                 | cmp                 ebx, eax

        $sequence_9 = { 49 c7460800000000 49 c70600000000 48 8b8528fbffff 49 }
            // n = 7, score = 100
            //   49                   | dec                 ecx
            //   c7460800000000       | mov                 dword ptr [esi + 8], 0
            //   49                   | dec                 ecx
            //   c70600000000         | mov                 dword ptr [esi], 0
            //   48                   | dec                 eax
            //   8b8528fbffff         | mov                 eax, dword ptr [ebp - 0x4d8]
            //   49                   | dec                 ecx

    condition:
        7 of them and filesize < 325376
}