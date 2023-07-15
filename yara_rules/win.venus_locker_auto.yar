rule win_venus_locker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.venus_locker"
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
        $sequence_0 = { 3a4041 f5 53 2efc 21b679098981 2400 d6 }
            // n = 7, score = 100
            //   3a4041               | cmp                 al, byte ptr [eax + 0x41]
            //   f5                   | cmc                 
            //   53                   | push                ebx
            //   2efc                 | cld                 
            //   21b679098981         | and                 dword ptr [esi - 0x7e76f687], esi
            //   2400                 | and                 al, 0
            //   d6                   | salc                

        $sequence_1 = { dccf fd daab3640ad80 46 }
            // n = 4, score = 100
            //   dccf                 | fmul                st(7), st(0)
            //   fd                   | std                 
            //   daab3640ad80         | fisubr              dword ptr [ebx - 0x7f52bfca]
            //   46                   | inc                 esi

        $sequence_2 = { 00d0 e059 0e 00e0 ed 3f }
            // n = 6, score = 100
            //   00d0                 | add                 al, dl
            //   e059                 | loopne              0x5b
            //   0e                   | push                cs
            //   00e0                 | add                 al, ah
            //   ed                   | in                  eax, dx
            //   3f                   | aas                 

        $sequence_3 = { b9b5ef0000 47 0fafca 304fff 47 }
            // n = 5, score = 100
            //   b9b5ef0000           | mov                 ecx, 0xefb5
            //   47                   | inc                 edi
            //   0fafca               | imul                ecx, edx
            //   304fff               | xor                 byte ptr [edi - 1], cl
            //   47                   | inc                 edi

        $sequence_4 = { a4 5d 19cb 7dc8 056014a006 c0dbb1 }
            // n = 6, score = 100
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   5d                   | pop                 ebp
            //   19cb                 | sbb                 ebx, ecx
            //   7dc8                 | jge                 0xffffffca
            //   056014a006           | add                 eax, 0x6a01460
            //   c0dbb1               | rcr                 bl, 0xb1

        $sequence_5 = { 58 6a01 e8???????? 8f461c c746140c000000 8d85ba010000 }
            // n = 6, score = 100
            //   58                   | pop                 eax
            //   6a01                 | push                1
            //   e8????????           |                     
            //   8f461c               | pop                 dword ptr [esi + 0x1c]
            //   c746140c000000       | mov                 dword ptr [esi + 0x14], 0xc
            //   8d85ba010000         | lea                 eax, [ebp + 0x1ba]

        $sequence_6 = { ce 8c9f021f4000 2640 9d 880c51 91 }
            // n = 6, score = 100
            //   ce                   | into                
            //   8c9f021f4000         | mov                 word ptr [edi + 0x401f02], ds
            //   2640                 | inc                 eax
            //   9d                   | popfd               
            //   880c51               | mov                 byte ptr [ecx + edx*2], cl
            //   91                   | xchg                eax, ecx

        $sequence_7 = { 13e0 fd 55 26023e ce 8c9f021f4000 2640 }
            // n = 7, score = 100
            //   13e0                 | adc                 esp, eax
            //   fd                   | std                 
            //   55                   | push                ebp
            //   26023e               | add                 bh, byte ptr es:[esi]
            //   ce                   | into                
            //   8c9f021f4000         | mov                 word ptr [edi + 0x401f02], ds
            //   2640                 | inc                 eax

        $sequence_8 = { b400 3b26 96 b335 7041 }
            // n = 5, score = 100
            //   b400                 | mov                 ah, 0
            //   3b26                 | cmp                 esp, dword ptr [esi]
            //   96                   | xchg                eax, esi
            //   b335                 | mov                 bl, 0x35
            //   7041                 | jo                  0x43

        $sequence_9 = { 00740061 007200 7400 4c 006900 6e }
            // n = 6, score = 100
            //   00740061             | add                 byte ptr [eax + eax + 0x61], dh
            //   007200               | add                 byte ptr [edx], dh
            //   7400                 | je                  2
            //   4c                   | dec                 esp
            //   006900               | add                 byte ptr [ecx], ch
            //   6e                   | outsb               dx, byte ptr [esi]

    condition:
        7 of them and filesize < 974848
}