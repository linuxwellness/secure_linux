rule win_koobface_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.koobface."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.koobface"
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
        $sequence_0 = { a5 83ec10 8bfc 8d75c8 a5 a5 a5 }
            // n = 7, score = 100
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   83ec10               | sub                 esp, 0x10
            //   8bfc                 | mov                 edi, esp
            //   8d75c8               | lea                 esi, [ebp - 0x38]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]

        $sequence_1 = { 8d8580feffff 50 c745fc2c000000 e8???????? 834dfcff 53 57 }
            // n = 7, score = 100
            //   8d8580feffff         | lea                 eax, [ebp - 0x180]
            //   50                   | push                eax
            //   c745fc2c000000       | mov                 dword ptr [ebp - 4], 0x2c
            //   e8????????           |                     
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   53                   | push                ebx
            //   57                   | push                edi

        $sequence_2 = { c70424e0930400 ffd6 8b85bca9ffff 69c060ea0000 50 ffd6 ff8568a2ffff }
            // n = 7, score = 100
            //   c70424e0930400       | mov                 dword ptr [esp], 0x493e0
            //   ffd6                 | call                esi
            //   8b85bca9ffff         | mov                 eax, dword ptr [ebp - 0x5644]
            //   69c060ea0000         | imul                eax, eax, 0xea60
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   ff8568a2ffff         | inc                 dword ptr [ebp - 0x5d98]

        $sequence_3 = { 740c 68???????? 68???????? eb70 83bd34c1ffff5a 8d85f0e8ffff 750c }
            // n = 7, score = 100
            //   740c                 | je                  0xe
            //   68????????           |                     
            //   68????????           |                     
            //   eb70                 | jmp                 0x72
            //   83bd34c1ffff5a       | cmp                 dword ptr [ebp - 0x3ecc], 0x5a
            //   8d85f0e8ffff         | lea                 eax, [ebp - 0x1710]
            //   750c                 | jne                 0xe

        $sequence_4 = { 83c40c 8d8528ffffff 50 8d8df0feffff e8???????? 8b8dccfdffff 8d85f0feffff }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8d8528ffffff         | lea                 eax, [ebp - 0xd8]
            //   50                   | push                eax
            //   8d8df0feffff         | lea                 ecx, [ebp - 0x110]
            //   e8????????           |                     
            //   8b8dccfdffff         | mov                 ecx, dword ptr [ebp - 0x234]
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]

        $sequence_5 = { 56 e8???????? 6a01 ff750c e8???????? 83ee80 56 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   6a01                 | push                1
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   83ee80               | sub                 esi, -0x80
            //   56                   | push                esi

        $sequence_6 = { 8b0c8da0534200 83e01f c1e006 f644080401 74cd 8b0408 }
            // n = 6, score = 100
            //   8b0c8da0534200       | mov                 ecx, dword ptr [ecx*4 + 0x4253a0]
            //   83e01f               | and                 eax, 0x1f
            //   c1e006               | shl                 eax, 6
            //   f644080401           | test                byte ptr [eax + ecx + 4], 1
            //   74cd                 | je                  0xffffffcf
            //   8b0408               | mov                 eax, dword ptr [eax + ecx]

        $sequence_7 = { 68???????? 8d8598faffff 50 53 8d85a4fbffff 50 57 }
            // n = 7, score = 100
            //   68????????           |                     
            //   8d8598faffff         | lea                 eax, [ebp - 0x568]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   8d85a4fbffff         | lea                 eax, [ebp - 0x45c]
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_8 = { 8d8528ffffff 50 8d8dd4feffff e8???????? 8b8dccfdffff 8d85d4feffff 50 }
            // n = 7, score = 100
            //   8d8528ffffff         | lea                 eax, [ebp - 0xd8]
            //   50                   | push                eax
            //   8d8dd4feffff         | lea                 ecx, [ebp - 0x12c]
            //   e8????????           |                     
            //   8b8dccfdffff         | mov                 ecx, dword ptr [ebp - 0x234]
            //   8d85d4feffff         | lea                 eax, [ebp - 0x12c]
            //   50                   | push                eax

        $sequence_9 = { 89460c 8d45bc 50 e8???????? 8b4dfc 83c40c 5f }
            // n = 7, score = 100
            //   89460c               | mov                 dword ptr [esi + 0xc], eax
            //   8d45bc               | lea                 eax, [ebp - 0x44]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c40c               | add                 esp, 0xc
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 368640
}