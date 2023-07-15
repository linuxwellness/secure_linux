rule win_maze_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.maze."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maze"
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
        $sequence_0 = { 8b450c f3aa 61 8945f0 c745f000000000 8b45f0 83c410 }
            // n = 7, score = 2400
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   61                   | popal               
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   83c410               | add                 esp, 0x10

        $sequence_1 = { 89e5 53 57 56 83ec10 8b4510 8b4d0c }
            // n = 7, score = 2400
            //   89e5                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   83ec10               | sub                 esp, 0x10
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_2 = { c745f000000000 eb17 60 8b7d08 8b4d10 8b450c }
            // n = 6, score = 2400
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   eb17                 | jmp                 0x19
            //   60                   | pushal              
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_3 = { c745f000000000 8b45f0 83c410 5e 5f 5b 5d }
            // n = 7, score = 2400
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   83c410               | add                 esp, 0x10
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp

        $sequence_4 = { 8945ec 894de8 8955e4 7509 c745f000000000 eb17 }
            // n = 6, score = 2400
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx
            //   7509                 | jne                 0xb
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   eb17                 | jmp                 0x19

        $sequence_5 = { 8b5508 837d0800 8945ec 894de8 }
            // n = 4, score = 2400
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx

        $sequence_6 = { 8b4510 8b4d0c 8b5508 837d0800 }
            // n = 4, score = 2400
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0

        $sequence_7 = { 898424ec000000 8b442430 83d200 899424a0000000 f7e6 898424e8010000 8b442408 }
            // n = 7, score = 2300
            //   898424ec000000       | mov                 dword ptr [esp + 0xec], eax
            //   8b442430             | mov                 eax, dword ptr [esp + 0x30]
            //   83d200               | adc                 edx, 0
            //   899424a0000000       | mov                 dword ptr [esp + 0xa0], edx
            //   f7e6                 | mul                 esi
            //   898424e8010000       | mov                 dword ptr [esp + 0x1e8], eax
            //   8b442408             | mov                 eax, dword ptr [esp + 8]

        $sequence_8 = { 41 41 41 41 41 41 41 }
            // n = 7, score = 1600
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx

        $sequence_9 = { 039481000c0000 8995f8feffff 8b55fc 8b4508 8b4c9034 c1e109 8b55fc }
            // n = 7, score = 100
            //   039481000c0000       | add                 edx, dword ptr [ecx + eax*4 + 0xc00]
            //   8995f8feffff         | mov                 dword ptr [ebp - 0x108], edx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4c9034             | mov                 ecx, dword ptr [eax + edx*4 + 0x34]
            //   c1e109               | shl                 ecx, 9
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_10 = { 8b4d08 03948100040000 89956cfeffff 8b55fc 8b4508 8b8c900c080000 038d70feffff }
            // n = 7, score = 100
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   03948100040000       | add                 edx, dword ptr [ecx + eax*4 + 0x400]
            //   89956cfeffff         | mov                 dword ptr [ebp - 0x194], edx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b8c900c080000       | mov                 ecx, dword ptr [eax + edx*4 + 0x80c]
            //   038d70feffff         | add                 ecx, dword ptr [ebp - 0x190]

        $sequence_11 = { 8b8c1000100000 c1e118 ba04000000 6bc207 8b5508 }
            // n = 5, score = 100
            //   8b8c1000100000       | mov                 ecx, dword ptr [eax + edx + 0x1000]
            //   c1e118               | shl                 ecx, 0x18
            //   ba04000000           | mov                 edx, 4
            //   6bc207               | imul                eax, edx, 7
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

        $sequence_12 = { 888d7afdffff 0fb6957bfdffff 0fb6857afdffff 8b4d08 }
            // n = 4, score = 100
            //   888d7afdffff         | mov                 byte ptr [ebp - 0x286], cl
            //   0fb6957bfdffff       | movzx               edx, byte ptr [ebp - 0x285]
            //   0fb6857afdffff       | movzx               eax, byte ptr [ebp - 0x286]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_13 = { 8b0c85acb04100 8b14856c814100 eb0c 8b15???????? }
            // n = 4, score = 100
            //   8b0c85acb04100       | mov                 ecx, dword ptr [eax*4 + 0x41b0ac]
            //   8b14856c814100       | mov                 edx, dword ptr [eax*4 + 0x41816c]
            //   eb0c                 | jmp                 0xe
            //   8b15????????         |                     

        $sequence_14 = { 89840a00100000 8b4dfc 8b5508 8b45d4 33448a04 b904000000 c1e100 }
            // n = 7, score = 100
            //   89840a00100000       | mov                 dword ptr [edx + ecx + 0x1000], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   33448a04             | xor                 eax, dword ptr [edx + ecx*4 + 4]
            //   b904000000           | mov                 ecx, 4
            //   c1e100               | shl                 ecx, 0

        $sequence_15 = { 894d80 8b5580 52 e8???????? 83c404 837d8000 }
            // n = 6, score = 100
            //   894d80               | mov                 dword ptr [ebp - 0x80], ecx
            //   8b5580               | mov                 edx, dword ptr [ebp - 0x80]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   837d8000             | cmp                 dword ptr [ebp - 0x80], 0

        $sequence_16 = { 0bc1 898500feffff ba04000000 6bc206 8b4d08 }
            // n = 5, score = 100
            //   0bc1                 | or                  eax, ecx
            //   898500feffff         | mov                 dword ptr [ebp - 0x200], eax
            //   ba04000000           | mov                 edx, 4
            //   6bc206               | imul                eax, edx, 6
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 2318336
}