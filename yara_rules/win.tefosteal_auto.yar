rule win_tefosteal_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tefosteal"
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
        $sequence_0 = { 0904957c0a6f00 b801000000 89d1 d3e0 0905???????? c3 }
            // n = 6, score = 200
            //   0904957c0a6f00       | or                  dword ptr [edx*4 + 0x6f0a7c], eax
            //   b801000000           | mov                 eax, 1
            //   89d1                 | mov                 ecx, edx
            //   d3e0                 | shl                 eax, cl
            //   0905????????         |                     
            //   c3                   | ret                 

        $sequence_1 = { 0f8328020000 8b45fc 8945e4 837de400 740b 8b45e4 83e804 }
            // n = 7, score = 200
            //   0f8328020000         | jae                 0x22e
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   837de400             | cmp                 dword ptr [ebp - 0x1c], 0
            //   740b                 | je                  0xd
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   83e804               | sub                 eax, 4

        $sequence_2 = { 68???????? 8d85dcfdffff e8???????? ffb5dcfdffff 68???????? 8d85d8fdffff e8???????? }
            // n = 7, score = 200
            //   68????????           |                     
            //   8d85dcfdffff         | lea                 eax, [ebp - 0x224]
            //   e8????????           |                     
            //   ffb5dcfdffff         | push                dword ptr [ebp - 0x224]
            //   68????????           |                     
            //   8d85d8fdffff         | lea                 eax, [ebp - 0x228]
            //   e8????????           |                     

        $sequence_3 = { 3bf3 7da7 3b750c 7e13 8b450c 50 56 }
            // n = 7, score = 200
            //   3bf3                 | cmp                 esi, ebx
            //   7da7                 | jge                 0xffffffa9
            //   3b750c               | cmp                 esi, dword ptr [ebp + 0xc]
            //   7e13                 | jle                 0x15
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_4 = { c3 53 56 8bf2 8bd8 56 8b4314 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8bf2                 | mov                 esi, edx
            //   8bd8                 | mov                 ebx, eax
            //   56                   | push                esi
            //   8b4314               | mov                 eax, dword ptr [ebx + 0x14]

        $sequence_5 = { 6a01 8bc8 49 8b55bc }
            // n = 4, score = 200
            //   6a01                 | push                1
            //   8bc8                 | mov                 ecx, eax
            //   49                   | dec                 ecx
            //   8b55bc               | mov                 edx, dword ptr [ebp - 0x44]

        $sequence_6 = { 83e804 8b00 668945de 66c745e00000 6a00 8d4dc6 8b55c0 }
            // n = 7, score = 200
            //   83e804               | sub                 eax, 4
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   668945de             | mov                 word ptr [ebp - 0x22], ax
            //   66c745e00000         | mov                 word ptr [ebp - 0x20], 0
            //   6a00                 | push                0
            //   8d4dc6               | lea                 ecx, [ebp - 0x3a]
            //   8b55c0               | mov                 edx, dword ptr [ebp - 0x40]

        $sequence_7 = { 52 50 8b4608 e8???????? 8b45fc 8945dc }
            // n = 6, score = 200
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax

        $sequence_8 = { 6801001f00 e8???????? 85c0 0f95c3 85c0 750e 68???????? }
            // n = 7, score = 200
            //   6801001f00           | push                0x1f0001
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f95c3               | setne               bl
            //   85c0                 | test                eax, eax
            //   750e                 | jne                 0x10
            //   68????????           |                     

        $sequence_9 = { 2114857c0a6f00 7507 0fb305???????? bff0ffffff 237efc 81ff600a0100 726c }
            // n = 7, score = 200
            //   2114857c0a6f00       | and                 dword ptr [eax*4 + 0x6f0a7c], edx
            //   7507                 | jne                 9
            //   0fb305????????       |                     
            //   bff0ffffff           | mov                 edi, 0xfffffff0
            //   237efc               | and                 edi, dword ptr [esi - 4]
            //   81ff600a0100         | cmp                 edi, 0x10a60
            //   726c                 | jb                  0x6e

    condition:
        7 of them and filesize < 7004160
}