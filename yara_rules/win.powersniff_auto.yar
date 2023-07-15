rule win_powersniff_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.powersniff."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.powersniff"
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
        $sequence_0 = { 895dec 895df0 ffd6 8945f4 3bc3 0f848a010000 57 }
            // n = 7, score = 100
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   ffd6                 | call                esi
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   3bc3                 | cmp                 eax, ebx
            //   0f848a010000         | je                  0x190
            //   57                   | push                edi

        $sequence_1 = { 6a01 8d5598 52 50 ff5130 8b45a0 }
            // n = 6, score = 100
            //   6a01                 | push                1
            //   8d5598               | lea                 edx, [ebp - 0x68]
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff5130               | call                dword ptr [ecx + 0x30]
            //   8b45a0               | mov                 eax, dword ptr [ebp - 0x60]

        $sequence_2 = { 8975fc ff75f8 6a00 ff35???????? ff15???????? 8b45fc 5f }
            // n = 7, score = 100
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   5f                   | pop                 edi

        $sequence_3 = { ffd3 8945fc 56 6a00 }
            // n = 4, score = 100
            //   ffd3                 | call                ebx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi
            //   6a00                 | push                0

        $sequence_4 = { ff7570 e8???????? 3bc3 0f8514010000 ff15???????? 50 }
            // n = 6, score = 100
            //   ff7570               | push                dword ptr [ebp + 0x70]
            //   e8????????           |                     
            //   3bc3                 | cmp                 eax, ebx
            //   0f8514010000         | jne                 0x11a
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_5 = { 8bec 51 8365fc00 53 56 57 6800000c00 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   6800000c00           | push                0xc0000

        $sequence_6 = { ff760c 895dec c745e804000000 ff15???????? }
            // n = 4, score = 100
            //   ff760c               | push                dword ptr [esi + 0xc]
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   c745e804000000       | mov                 dword ptr [ebp - 0x18], 4
            //   ff15????????         |                     

        $sequence_7 = { 40 ebf6 55 8bec 83ec74 53 56 }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   ebf6                 | jmp                 0xfffffff8
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec74               | sub                 esp, 0x74
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_8 = { bbc1000000 0f82c4000000 8b4508 56 8b703c 81fe00020000 0f8fb0000000 }
            // n = 7, score = 100
            //   bbc1000000           | mov                 ebx, 0xc1
            //   0f82c4000000         | jb                  0xca
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   8b703c               | mov                 esi, dword ptr [eax + 0x3c]
            //   81fe00020000         | cmp                 esi, 0x200
            //   0f8fb0000000         | jg                  0xb6

        $sequence_9 = { 8bda c1eb10 0fb6f3 8b34b5907c0010 8b5df8 c1eb08 0fb6db }
            // n = 7, score = 100
            //   8bda                 | mov                 ebx, edx
            //   c1eb10               | shr                 ebx, 0x10
            //   0fb6f3               | movzx               esi, bl
            //   8b34b5907c0010       | mov                 esi, dword ptr [esi*4 + 0x10007c90]
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   c1eb08               | shr                 ebx, 8
            //   0fb6db               | movzx               ebx, bl

    condition:
        7 of them and filesize < 90112
}