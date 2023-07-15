rule win_glupteba_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.glupteba."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glupteba"
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
        $sequence_0 = { 0fb675ff 0fb6c3 99 f7fe 8ac8 f66dfe 3045fd }
            // n = 7, score = 400
            //   0fb675ff             | movzx               esi, byte ptr [ebp - 1]
            //   0fb6c3               | movzx               eax, bl
            //   99                   | cdq                 
            //   f7fe                 | idiv                esi
            //   8ac8                 | mov                 cl, al
            //   f66dfe               | imul                byte ptr [ebp - 2]
            //   3045fd               | xor                 byte ptr [ebp - 3], al

        $sequence_1 = { 8a4b07 884306 8a4607 32c8 884f07 }
            // n = 5, score = 400
            //   8a4b07               | mov                 cl, byte ptr [ebx + 7]
            //   884306               | mov                 byte ptr [ebx + 6], al
            //   8a4607               | mov                 al, byte ptr [esi + 7]
            //   32c8                 | xor                 cl, al
            //   884f07               | mov                 byte ptr [edi + 7], cl

        $sequence_2 = { 0f8498020000 68???????? ffd6 3bc7 a3???????? }
            // n = 5, score = 400
            //   0f8498020000         | je                  0x29e
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   3bc7                 | cmp                 eax, edi
            //   a3????????           |                     

        $sequence_3 = { a3???????? ff15???????? ff75f8 e8???????? }
            // n = 4, score = 400
            //   a3????????           |                     
            //   ff15????????         |                     
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   e8????????           |                     

        $sequence_4 = { 8b4510 33480c 8b450c 897808 8910 8b55d4 5f }
            // n = 7, score = 400
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   33480c               | xor                 ecx, dword ptr [eax + 0xc]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   897808               | mov                 dword ptr [eax + 8], edi
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b55d4               | mov                 edx, dword ptr [ebp - 0x2c]
            //   5f                   | pop                 edi

        $sequence_5 = { b900040000 8dbdddefffff f3ab 763b ba00100000 }
            // n = 5, score = 400
            //   b900040000           | mov                 ecx, 0x400
            //   8dbdddefffff         | lea                 edi, [ebp - 0x1023]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   763b                 | jbe                 0x3d
            //   ba00100000           | mov                 edx, 0x1000

        $sequence_6 = { 8b5df8 33cb 8977fc 895f04 894f08 83c710 837d0824 }
            // n = 7, score = 400
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   33cb                 | xor                 ecx, ebx
            //   8977fc               | mov                 dword ptr [edi - 4], esi
            //   895f04               | mov                 dword ptr [edi + 4], ebx
            //   894f08               | mov                 dword ptr [edi + 8], ecx
            //   83c710               | add                 edi, 0x10
            //   837d0824             | cmp                 dword ptr [ebp + 8], 0x24

        $sequence_7 = { 8b75f4 6bff1b c1e608 0b75fc c1e308 81e67f7f7fff 0bf3 }
            // n = 7, score = 400
            //   8b75f4               | mov                 esi, dword ptr [ebp - 0xc]
            //   6bff1b               | imul                edi, edi, 0x1b
            //   c1e608               | shl                 esi, 8
            //   0b75fc               | or                  esi, dword ptr [ebp - 4]
            //   c1e308               | shl                 ebx, 8
            //   81e67f7f7fff         | and                 esi, 0xff7f7f7f
            //   0bf3                 | or                  esi, ebx

        $sequence_8 = { 0106 830702 392e 75a0 }
            // n = 4, score = 100
            //   0106                 | add                 dword ptr [esi], eax
            //   830702               | add                 dword ptr [edi], 2
            //   392e                 | cmp                 dword ptr [esi], ebp
            //   75a0                 | jne                 0xffffffa2

        $sequence_9 = { 005e3e 46 00ff 3e46 }
            // n = 4, score = 100
            //   005e3e               | add                 byte ptr [esi + 0x3e], bl
            //   46                   | inc                 esi
            //   00ff                 | add                 bh, bh
            //   3e46                 | inc                 esi

        $sequence_10 = { 00ff 3e46 0012 3f }
            // n = 4, score = 100
            //   00ff                 | add                 bh, bh
            //   3e46                 | inc                 esi
            //   0012                 | add                 byte ptr [edx], dl
            //   3f                   | aas                 

        $sequence_11 = { 0101 03d3 8b4620 8bcb }
            // n = 4, score = 100
            //   0101                 | add                 dword ptr [ecx], eax
            //   03d3                 | add                 edx, ebx
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   8bcb                 | mov                 ecx, ebx

        $sequence_12 = { 0012 3f 46 008bff558bec }
            // n = 4, score = 100
            //   0012                 | add                 byte ptr [edx], dl
            //   3f                   | aas                 
            //   46                   | inc                 esi
            //   008bff558bec         | add                 byte ptr [ebx - 0x1374aa01], cl

        $sequence_13 = { 00cd 3e46 005e3e 46 }
            // n = 4, score = 100
            //   00cd                 | add                 ch, cl
            //   3e46                 | inc                 esi
            //   005e3e               | add                 byte ptr [esi + 0x3e], bl
            //   46                   | inc                 esi

        $sequence_14 = { 00f1 3d46005e3e 46 00cd }
            // n = 4, score = 100
            //   00f1                 | add                 cl, dh
            //   3d46005e3e           | cmp                 eax, 0x3e5e0046
            //   46                   | inc                 esi
            //   00cd                 | add                 ch, cl

        $sequence_15 = { 0107 eb4d 8b02 89442418 }
            // n = 4, score = 100
            //   0107                 | add                 dword ptr [edi], eax
            //   eb4d                 | jmp                 0x4f
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   89442418             | mov                 dword ptr [esp + 0x18], eax

    condition:
        7 of them and filesize < 1417216
}