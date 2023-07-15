rule win_manitsme_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.manitsme."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.manitsme"
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
        $sequence_0 = { 8b842428010000 56 51 68???????? a3???????? }
            // n = 5, score = 100
            //   8b842428010000       | mov                 eax, dword ptr [esp + 0x128]
            //   56                   | push                esi
            //   51                   | push                ecx
            //   68????????           |                     
            //   a3????????           |                     

        $sequence_1 = { 8d442420 50 6a00 6a00 8d4c2434 51 6a00 }
            // n = 7, score = 100
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d4c2434             | lea                 ecx, [esp + 0x34]
            //   51                   | push                ecx
            //   6a00                 | push                0

        $sequence_2 = { 83c404 52 ffd5 e9???????? 68bb010000 66c74424180200 }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   52                   | push                edx
            //   ffd5                 | call                ebp
            //   e9????????           |                     
            //   68bb010000           | push                0x1bb
            //   66c74424180200       | mov                 word ptr [esp + 0x18], 2

        $sequence_3 = { 56 6a01 89442448 6a02 8d442454 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   6a01                 | push                1
            //   89442448             | mov                 dword ptr [esp + 0x48], eax
            //   6a02                 | push                2
            //   8d442454             | lea                 eax, [esp + 0x54]

        $sequence_4 = { 56 57 6a1c c744241400000000 e8???????? }
            // n = 5, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a1c                 | push                0x1c
            //   c744241400000000     | mov                 dword ptr [esp + 0x14], 0
            //   e8????????           |                     

        $sequence_5 = { b902000000 52 bd07000000 bbb80b0000 50 c744241c10000000 890d???????? }
            // n = 7, score = 100
            //   b902000000           | mov                 ecx, 2
            //   52                   | push                edx
            //   bd07000000           | mov                 ebp, 7
            //   bbb80b0000           | mov                 ebx, 0xbb8
            //   50                   | push                eax
            //   c744241c10000000     | mov                 dword ptr [esp + 0x1c], 0x10
            //   890d????????         |                     

        $sequence_6 = { ffd5 e9???????? 68bb010000 66c74424180200 }
            // n = 4, score = 100
            //   ffd5                 | call                ebp
            //   e9????????           |                     
            //   68bb010000           | push                0x1bb
            //   66c74424180200       | mov                 word ptr [esp + 0x18], 2

        $sequence_7 = { 5f 5b c9 c3 6a0a 6a00 ff74240c }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c3                   | ret                 
            //   6a0a                 | push                0xa
            //   6a00                 | push                0
            //   ff74240c             | push                dword ptr [esp + 0xc]

        $sequence_8 = { ff15???????? 8d942440030000 8bc6 2bd6 8a08 880c02 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8d942440030000       | lea                 edx, [esp + 0x340]
            //   8bc6                 | mov                 eax, esi
            //   2bd6                 | sub                 edx, esi
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   880c02               | mov                 byte ptr [edx + eax], cl

        $sequence_9 = { 51 687fffffff 68ffff0000 52 ff15???????? }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   687fffffff           | push                0xffffff7f
            //   68ffff0000           | push                0xffff
            //   52                   | push                edx
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 212992
}