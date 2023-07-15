rule win_afrodita_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.afrodita."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.afrodita"
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
        $sequence_0 = { e8???????? 8d45a0 c745d4ffffffff 8945dc 8d4da0 8d8571ffffff c645d800 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8d45a0               | lea                 eax, [ebp - 0x60]
            //   c745d4ffffffff       | mov                 dword ptr [ebp - 0x2c], 0xffffffff
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   8d4da0               | lea                 ecx, [ebp - 0x60]
            //   8d8571ffffff         | lea                 eax, [ebp - 0x8f]
            //   c645d800             | mov                 byte ptr [ebp - 0x28], 0

        $sequence_1 = { c745fc11000000 50 8d8d70ffffff 895dec e8???????? c645f300 85c0 }
            // n = 7, score = 300
            //   c745fc11000000       | mov                 dword ptr [ebp - 4], 0x11
            //   50                   | push                eax
            //   8d8d70ffffff         | lea                 ecx, [ebp - 0x90]
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   e8????????           |                     
            //   c645f300             | mov                 byte ptr [ebp - 0xd], 0
            //   85c0                 | test                eax, eax

        $sequence_2 = { 8d4dec 2bc3 c1f802 c1e005 034510 50 e8???????? }
            // n = 7, score = 300
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   2bc3                 | sub                 eax, ebx
            //   c1f802               | sar                 eax, 2
            //   c1e005               | shl                 eax, 5
            //   034510               | add                 eax, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_3 = { 0b480c 83e115 83c902 89480c 8b4010 23c1 756e }
            // n = 7, score = 300
            //   0b480c               | or                  ecx, dword ptr [eax + 0xc]
            //   83e115               | and                 ecx, 0x15
            //   83c902               | or                  ecx, 2
            //   89480c               | mov                 dword ptr [eax + 0xc], ecx
            //   8b4010               | mov                 eax, dword ptr [eax + 0x10]
            //   23c1                 | and                 eax, ecx
            //   756e                 | jne                 0x70

        $sequence_4 = { 57 8b4040 ffd0 8bca 8b5514 3bd1 7709 }
            // n = 7, score = 300
            //   57                   | push                edi
            //   8b4040               | mov                 eax, dword ptr [eax + 0x40]
            //   ffd0                 | call                eax
            //   8bca                 | mov                 ecx, edx
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
            //   3bd1                 | cmp                 edx, ecx
            //   7709                 | ja                  0xb

        $sequence_5 = { e8???????? 8d85fcfeffff 8bcb 50 e8???????? 8d45d0 }
            // n = 6, score = 300
            //   e8????????           |                     
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   8bcb                 | mov                 ecx, ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d45d0               | lea                 eax, [ebp - 0x30]

        $sequence_6 = { c7461000000000 c746140f000000 c60600 e9???????? 6a00 ffb57cffffff 8d4dd8 }
            // n = 7, score = 300
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   c60600               | mov                 byte ptr [esi], 0
            //   e9????????           |                     
            //   6a00                 | push                0
            //   ffb57cffffff         | push                dword ptr [ebp - 0x84]
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]

        $sequence_7 = { 0f8283f5ffff 8b5508 8d8d78ffffff 89bd78ffffff 2bca 5f }
            // n = 6, score = 300
            //   0f8283f5ffff         | jb                  0xfffff589
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8d8d78ffffff         | lea                 ecx, [ebp - 0x88]
            //   89bd78ffffff         | mov                 dword ptr [ebp - 0x88], edi
            //   2bca                 | sub                 ecx, edx
            //   5f                   | pop                 edi

        $sequence_8 = { ff75e8 0f4345d8 8d4dc0 50 e8???????? 8d45c0 }
            // n = 6, score = 300
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   0f4345d8             | cmovae              eax, dword ptr [ebp - 0x28]
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d45c0               | lea                 eax, [ebp - 0x40]

        $sequence_9 = { c645fc0d 33c0 56 8b11 8bca f3ab 85d2 }
            // n = 7, score = 300
            //   c645fc0d             | mov                 byte ptr [ebp - 4], 0xd
            //   33c0                 | xor                 eax, eax
            //   56                   | push                esi
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8bca                 | mov                 ecx, edx
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   85d2                 | test                edx, edx

    condition:
        7 of them and filesize < 2334720
}