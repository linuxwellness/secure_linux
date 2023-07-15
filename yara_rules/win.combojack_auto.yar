rule win_combojack_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.combojack"
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
        $sequence_0 = { 29ff 2f 2d29ff2f2d 29ff 302e 2aff 2f }
            // n = 7, score = 100
            //   29ff                 | sub                 edi, edi
            //   2f                   | das                 
            //   2d29ff2f2d           | sub                 eax, 0x2d2fff29
            //   29ff                 | sub                 edi, edi
            //   302e                 | xor                 byte ptr [esi], ch
            //   2aff                 | sub                 bh, bh
            //   2f                   | das                 

        $sequence_1 = { 897f1c c7471804455300 a1???????? 89470c 8d4724 8bd6 }
            // n = 6, score = 100
            //   897f1c               | mov                 dword ptr [edi + 0x1c], edi
            //   c7471804455300       | mov                 dword ptr [edi + 0x18], 0x534504
            //   a1????????           |                     
            //   89470c               | mov                 dword ptr [edi + 0xc], eax
            //   8d4724               | lea                 eax, [edi + 0x24]
            //   8bd6                 | mov                 edx, esi

        $sequence_2 = { c1ee04 8b04b538d45700 50 68000000c0 8bc7 e8???????? }
            // n = 6, score = 100
            //   c1ee04               | shr                 esi, 4
            //   8b04b538d45700       | mov                 eax, dword ptr [esi*4 + 0x57d438]
            //   50                   | push                eax
            //   68000000c0           | push                0xc0000000
            //   8bc7                 | mov                 eax, edi
            //   e8????????           |                     

        $sequence_3 = { 00c6 ff00 0028 3658 00c7 ff00 0028 }
            // n = 7, score = 100
            //   00c6                 | add                 dh, al
            //   ff00                 | inc                 dword ptr [eax]
            //   0028                 | add                 byte ptr [eax], ch
            //   3658                 | pop                 eax
            //   00c7                 | add                 bh, al
            //   ff00                 | inc                 dword ptr [eax]
            //   0028                 | add                 byte ptr [eax], ch

        $sequence_4 = { 00ce ff00 0028 3658 00cf ff00 0028 }
            // n = 7, score = 100
            //   00ce                 | add                 dh, cl
            //   ff00                 | inc                 dword ptr [eax]
            //   0028                 | add                 byte ptr [eax], ch
            //   3658                 | pop                 eax
            //   00cf                 | add                 bh, cl
            //   ff00                 | inc                 dword ptr [eax]
            //   0028                 | add                 byte ptr [eax], ch

        $sequence_5 = { 897f14 c74710a4594a00 897f1c c74718b0594a00 a1???????? 89470c }
            // n = 6, score = 100
            //   897f14               | mov                 dword ptr [edi + 0x14], edi
            //   c74710a4594a00       | mov                 dword ptr [edi + 0x10], 0x4a59a4
            //   897f1c               | mov                 dword ptr [edi + 0x1c], edi
            //   c74718b0594a00       | mov                 dword ptr [edi + 0x18], 0x4a59b0
            //   a1????????           |                     
            //   89470c               | mov                 dword ptr [edi + 0xc], eax

        $sequence_6 = { 8d45c4 8b55ec e8???????? 8b45c4 50 e8???????? 5a }
            // n = 7, score = 100
            //   8d45c4               | lea                 eax, [ebp - 0x3c]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   e8????????           |                     
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   5a                   | pop                 edx

        $sequence_7 = { e8???????? 0f94c0 83e07f 8b1c8510f45700 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   0f94c0               | sete                al
            //   83e07f               | and                 eax, 0x7f
            //   8b1c8510f45700       | mov                 ebx, dword ptr [eax*4 + 0x57f410]

        $sequence_8 = { 8b45f8 8b10 ff5218 85c0 0f94c0 83e07f ff348534df5700 }
            // n = 7, score = 100
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   ff5218               | call                dword ptr [edx + 0x18]
            //   85c0                 | test                eax, eax
            //   0f94c0               | sete                al
            //   83e07f               | and                 eax, 0x7f
            //   ff348534df5700       | push                dword ptr [eax*4 + 0x57df34]

        $sequence_9 = { 8b45fc 66833830 751a 8d45bc 8b55e4 e8???????? 8b45bc }
            // n = 7, score = 100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   66833830             | cmp                 word ptr [eax], 0x30
            //   751a                 | jne                 0x1c
            //   8d45bc               | lea                 eax, [ebp - 0x44]
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   e8????????           |                     
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]

    condition:
        7 of them and filesize < 3620864
}