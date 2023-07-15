rule win_grillmark_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.grillmark."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grillmark"
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
        $sequence_0 = { 7403 6a01 5b ff75fc e8???????? 8bc3 }
            // n = 6, score = 300
            //   7403                 | je                  5
            //   6a01                 | push                1
            //   5b                   | pop                 ebx
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8bc3                 | mov                 eax, ebx

        $sequence_1 = { aa 8b3d???????? 8d45b4 50 e8???????? 59 85c0 }
            // n = 7, score = 300
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8b3d????????         |                     
            //   8d45b4               | lea                 eax, [ebp - 0x4c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_2 = { 59 50 6a01 8d85f0feffff 53 50 6803000080 }
            // n = 7, score = 300
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   6a01                 | push                1
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   6803000080           | push                0x80000003

        $sequence_3 = { ff15???????? 56 ff15???????? ff75ec ff15???????? 5e 395df8 }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff15????????         |                     
            //   5e                   | pop                 esi
            //   395df8               | cmp                 dword ptr [ebp - 8], ebx

        $sequence_4 = { ff7510 8d85a8feffff ff750c ff7508 ff7508 68???????? }
            // n = 6, score = 300
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8d85a8feffff         | lea                 eax, [ebp - 0x158]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   68????????           |                     

        $sequence_5 = { 6a09 ab 59 8d7dc0 8975bc 8975f8 }
            // n = 6, score = 300
            //   6a09                 | push                9
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   59                   | pop                 ecx
            //   8d7dc0               | lea                 edi, [ebp - 0x40]
            //   8975bc               | mov                 dword ptr [ebp - 0x44], esi
            //   8975f8               | mov                 dword ptr [ebp - 8], esi

        $sequence_6 = { 50 e8???????? 59 e8???????? 85c0 746e }
            // n = 6, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   746e                 | je                  0x70

        $sequence_7 = { ebf1 3810 7504 33c0 }
            // n = 4, score = 300
            //   ebf1                 | jmp                 0xfffffff3
            //   3810                 | cmp                 byte ptr [eax], dl
            //   7504                 | jne                 6
            //   33c0                 | xor                 eax, eax

        $sequence_8 = { 03c6 46 e8???????? 3bf0 59 72c5 8b45fc }
            // n = 7, score = 300
            //   03c6                 | add                 eax, esi
            //   46                   | inc                 esi
            //   e8????????           |                     
            //   3bf0                 | cmp                 esi, eax
            //   59                   | pop                 ecx
            //   72c5                 | jb                  0xffffffc7
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_9 = { 8945fc 0f84b8000000 56 e8???????? 50 }
            // n = 5, score = 300
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   0f84b8000000         | je                  0xbe
            //   56                   | push                esi
            //   e8????????           |                     
            //   50                   | push                eax

    condition:
        7 of them and filesize < 212992
}