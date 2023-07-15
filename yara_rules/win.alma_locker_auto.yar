rule win_alma_locker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.alma_locker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alma_locker"
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
        $sequence_0 = { 8bd0 c645fc0c 8d8d74ffffff e8???????? }
            // n = 4, score = 100
            //   8bd0                 | mov                 edx, eax
            //   c645fc0c             | mov                 byte ptr [ebp - 4], 0xc
            //   8d8d74ffffff         | lea                 ecx, [ebp - 0x8c]
            //   e8????????           |                     

        $sequence_1 = { e9???????? 8d8db0faffff e9???????? 8d8d68faffff e9???????? 8d8d38faffff e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d8db0faffff         | lea                 ecx, [ebp - 0x550]
            //   e9????????           |                     
            //   8d8d68faffff         | lea                 ecx, [ebp - 0x598]
            //   e9????????           |                     
            //   8d8d38faffff         | lea                 ecx, [ebp - 0x5c8]
            //   e9????????           |                     

        $sequence_2 = { e9???????? 8d8d9cfeffff e9???????? 8d8d44ffffff e9???????? 8d8d14ffffff e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d8d9cfeffff         | lea                 ecx, [ebp - 0x164]
            //   e9????????           |                     
            //   8d8d44ffffff         | lea                 ecx, [ebp - 0xbc]
            //   e9????????           |                     
            //   8d8d14ffffff         | lea                 ecx, [ebp - 0xec]
            //   e9????????           |                     

        $sequence_3 = { 8bd0 8d8d2cffffff e8???????? 8bf0 83c404 }
            // n = 5, score = 100
            //   8bd0                 | mov                 edx, eax
            //   8d8d2cffffff         | lea                 ecx, [ebp - 0xd4]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c404               | add                 esp, 4

        $sequence_4 = { 8b8528e5ffff 8b0485e86a0210 ff3401 ff15???????? 85c0 0f84ed000000 83bd38e5ffff01 }
            // n = 7, score = 100
            //   8b8528e5ffff         | mov                 eax, dword ptr [ebp - 0x1ad8]
            //   8b0485e86a0210       | mov                 eax, dword ptr [eax*4 + 0x10026ae8]
            //   ff3401               | push                dword ptr [ecx + eax]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84ed000000         | je                  0xf3
            //   83bd38e5ffff01       | cmp                 dword ptr [ebp - 0x1ac8], 1

        $sequence_5 = { 83c404 33c0 c78540ffffff07000000 83bdc8feffff08 }
            // n = 4, score = 100
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   c78540ffffff07000000     | mov    dword ptr [ebp - 0xc0], 7
            //   83bdc8feffff08       | cmp                 dword ptr [ebp - 0x138], 8

        $sequence_6 = { 84c0 0f94c0 84c0 0f8496060000 }
            // n = 4, score = 100
            //   84c0                 | test                al, al
            //   0f94c0               | sete                al
            //   84c0                 | test                al, al
            //   0f8496060000         | je                  0x69c

        $sequence_7 = { c68588fbffff00 c78598fbffff00000000 c7859cfbffff0f000000 720e ffb5b8fbffff }
            // n = 5, score = 100
            //   c68588fbffff00       | mov                 byte ptr [ebp - 0x478], 0
            //   c78598fbffff00000000     | mov    dword ptr [ebp - 0x468], 0
            //   c7859cfbffff0f000000     | mov    dword ptr [ebp - 0x464], 0xf
            //   720e                 | jb                  0x10
            //   ffb5b8fbffff         | push                dword ptr [ebp - 0x448]

        $sequence_8 = { 0f44c1 c705????????00000000 50 68???????? b9???????? e8???????? c645fc07 }
            // n = 7, score = 100
            //   0f44c1               | cmove               eax, ecx
            //   c705????????00000000     |     
            //   50                   | push                eax
            //   68????????           |                     
            //   b9????????           |                     
            //   e8????????           |                     
            //   c645fc07             | mov                 byte ptr [ebp - 4], 7

        $sequence_9 = { 50 ba???????? c745fc07000000 8d4dd8 e8???????? 83c40c 6aff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ba????????           |                     
            //   c745fc07000000       | mov                 dword ptr [ebp - 4], 7
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6aff                 | push                -1

    condition:
        7 of them and filesize < 335872
}