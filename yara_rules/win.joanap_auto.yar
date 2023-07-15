rule win_joanap_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.joanap."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.joanap"
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
        $sequence_0 = { 8b542418 8b4214 85c0 7434 6a01 8d442424 6820bf0200 }
            // n = 7, score = 100
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   8b4214               | mov                 eax, dword ptr [edx + 0x14]
            //   85c0                 | test                eax, eax
            //   7434                 | je                  0x36
            //   6a01                 | push                1
            //   8d442424             | lea                 eax, [esp + 0x24]
            //   6820bf0200           | push                0x2bf20

        $sequence_1 = { 55 ff15???????? 85c0 7422 e9???????? 83fbff 7418 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7422                 | je                  0x24
            //   e9????????           |                     
            //   83fbff               | cmp                 ebx, -1
            //   7418                 | je                  0x1a

        $sequence_2 = { 81c408100000 c3 8d542404 52 56 e8???????? 83c408 }
            // n = 7, score = 100
            //   81c408100000         | add                 esp, 0x1008
            //   c3                   | ret                 
            //   8d542404             | lea                 edx, [esp + 4]
            //   52                   | push                edx
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_3 = { 8d4c2404 8d54240c 51 52 8d842494000000 6880000000 }
            // n = 6, score = 100
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   8d54240c             | lea                 edx, [esp + 0xc]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   8d842494000000       | lea                 eax, [esp + 0x94]
            //   6880000000           | push                0x80

        $sequence_4 = { 83c410 83f8ff 0f85e9feffff 68???????? ff15???????? 8935???????? 5f }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   83f8ff               | cmp                 eax, -1
            //   0f85e9feffff         | jne                 0xfffffeef
            //   68????????           |                     
            //   ff15????????         |                     
            //   8935????????         |                     
            //   5f                   | pop                 edi

        $sequence_5 = { 813800000001 0f831c030000 85c9 750c 813800000001 0f820c030000 8d4c2414 }
            // n = 7, score = 100
            //   813800000001         | cmp                 dword ptr [eax], 0x1000000
            //   0f831c030000         | jae                 0x322
            //   85c9                 | test                ecx, ecx
            //   750c                 | jne                 0xe
            //   813800000001         | cmp                 dword ptr [eax], 0x1000000
            //   0f820c030000         | jb                  0x312
            //   8d4c2414             | lea                 ecx, [esp + 0x14]

        $sequence_6 = { bf???????? 6804010000 f3ab b970300000 bf???????? f3ab b92c010000 }
            // n = 7, score = 100
            //   bf????????           |                     
            //   6804010000           | push                0x104
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   b970300000           | mov                 ecx, 0x3070
            //   bf????????           |                     
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   b92c010000           | mov                 ecx, 0x12c

        $sequence_7 = { 0f8570020000 8d0c49 8d54241c 52 6a1e 668b44cb04 }
            // n = 6, score = 100
            //   0f8570020000         | jne                 0x276
            //   8d0c49               | lea                 ecx, [ecx + ecx*2]
            //   8d54241c             | lea                 edx, [esp + 0x1c]
            //   52                   | push                edx
            //   6a1e                 | push                0x1e
            //   668b44cb04           | mov                 ax, word ptr [ebx + ecx*8 + 4]

        $sequence_8 = { 83c410 a3???????? 6a00 6a00 6a00 68???????? 6a00 }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   a3????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   6a00                 | push                0

        $sequence_9 = { e8???????? 83c410 83f8ff 741a 68???????? ff15???????? 66817c24140240 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   83f8ff               | cmp                 eax, -1
            //   741a                 | je                  0x1c
            //   68????????           |                     
            //   ff15????????         |                     
            //   66817c24140240       | cmp                 word ptr [esp + 0x14], 0x4002

    condition:
        7 of them and filesize < 270336
}