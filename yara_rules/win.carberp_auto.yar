rule win_carberp_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.carberp."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.carberp"
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
        $sequence_0 = { ffd0 c3 68d570346b 6a0f 6a00 e8???????? 83c40c }
            // n = 7, score = 200
            //   ffd0                 | call                eax
            //   c3                   | ret                 
            //   68d570346b           | push                0x6b3470d5
            //   6a0f                 | push                0xf
            //   6a00                 | push                0
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { ff742408 ff742408 ffd0 c3 68192b9095 6a01 6a00 }
            // n = 7, score = 200
            //   ff742408             | push                dword ptr [esp + 8]
            //   ff742408             | push                dword ptr [esp + 8]
            //   ffd0                 | call                eax
            //   c3                   | ret                 
            //   68192b9095           | push                0x95902b19
            //   6a01                 | push                1
            //   6a00                 | push                0

        $sequence_2 = { e8???????? e8???????? b001 c3 68836927f2 6a07 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   e8????????           |                     
            //   b001                 | mov                 al, 1
            //   c3                   | ret                 
            //   68836927f2           | push                0xf2276983
            //   6a07                 | push                7

        $sequence_3 = { c9 c3 ff7508 e8???????? 59 59 8945fc }
            // n = 7, score = 200
            //   c9                   | leave               
            //   c3                   | ret                 
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_4 = { 53 6a44 33db 8d45ac 53 50 e8???????? }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   6a44                 | push                0x44
            //   33db                 | xor                 ebx, ebx
            //   8d45ac               | lea                 eax, [ebp - 0x54]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_5 = { ff74240c ffd0 c3 681d5b931f 6a04 6a00 e8???????? }
            // n = 7, score = 200
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   ffd0                 | call                eax
            //   c3                   | ret                 
            //   681d5b931f           | push                0x1f935b1d
            //   6a04                 | push                4
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_6 = { ff7508 e8???????? 59 8945ec 3bc3 0f84f5000000 395d14 }
            // n = 7, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   3bc3                 | cmp                 eax, ebx
            //   0f84f5000000         | je                  0xfb
            //   395d14               | cmp                 dword ptr [ebp + 0x14], ebx

        $sequence_7 = { c645486e 885d49 c6450057 c6450169 c645026e c6450364 c645046f }
            // n = 7, score = 200
            //   c645486e             | mov                 byte ptr [ebp + 0x48], 0x6e
            //   885d49               | mov                 byte ptr [ebp + 0x49], bl
            //   c6450057             | mov                 byte ptr [ebp], 0x57
            //   c6450169             | mov                 byte ptr [ebp + 1], 0x69
            //   c645026e             | mov                 byte ptr [ebp + 2], 0x6e
            //   c6450364             | mov                 byte ptr [ebp + 3], 0x64
            //   c645046f             | mov                 byte ptr [ebp + 4], 0x6f

        $sequence_8 = { 81ec30020000 56 6a00 6a02 e8???????? 8d8dd0fdffff 51 }
            // n = 7, score = 200
            //   81ec30020000         | sub                 esp, 0x230
            //   56                   | push                esi
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   e8????????           |                     
            //   8d8dd0fdffff         | lea                 ecx, [ebp - 0x230]
            //   51                   | push                ecx

        $sequence_9 = { ff7508 50 56 e8???????? ff7658 e8???????? 83c418 }
            // n = 7, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   ff7658               | push                dword ptr [esi + 0x58]
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18

    condition:
        7 of them and filesize < 491520
}