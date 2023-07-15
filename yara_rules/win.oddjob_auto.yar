rule win_oddjob_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.oddjob."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oddjob"
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
        $sequence_0 = { 56 8d85f4fdffff 50 be04010000 56 ff15???????? }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8d85f4fdffff         | lea                 eax, [ebp - 0x20c]
            //   50                   | push                eax
            //   be04010000           | mov                 esi, 0x104
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_1 = { c685a1faffff7e c685a2faffff79 c685a3faffff52 c685a4faffff8b c685a5faffff4b c685a6fafffffc }
            // n = 6, score = 100
            //   c685a1faffff7e       | mov                 byte ptr [ebp - 0x55f], 0x7e
            //   c685a2faffff79       | mov                 byte ptr [ebp - 0x55e], 0x79
            //   c685a3faffff52       | mov                 byte ptr [ebp - 0x55d], 0x52
            //   c685a4faffff8b       | mov                 byte ptr [ebp - 0x55c], 0x8b
            //   c685a5faffff4b       | mov                 byte ptr [ebp - 0x55b], 0x4b
            //   c685a6fafffffc       | mov                 byte ptr [ebp - 0x55a], 0xfc

        $sequence_2 = { ff75ec e8???????? 8bf8 3bfb 59 7429 }
            // n = 6, score = 100
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   3bfb                 | cmp                 edi, ebx
            //   59                   | pop                 ecx
            //   7429                 | je                  0x2b

        $sequence_3 = { 5d c3 ff07 5d c3 8bff }
            // n = 6, score = 100
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   ff07                 | inc                 dword ptr [edi]
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi

        $sequence_4 = { 85c0 741e 8bc6 33ff }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   741e                 | je                  0x20
            //   8bc6                 | mov                 eax, esi
            //   33ff                 | xor                 edi, edi

        $sequence_5 = { c6858cfdffff83 c6858dfdffffc3 c6858efdffff1a c6858ffdffff8b c68590fdffff34 c68591fdffff93 c68592fdffff5b }
            // n = 7, score = 100
            //   c6858cfdffff83       | mov                 byte ptr [ebp - 0x274], 0x83
            //   c6858dfdffffc3       | mov                 byte ptr [ebp - 0x273], 0xc3
            //   c6858efdffff1a       | mov                 byte ptr [ebp - 0x272], 0x1a
            //   c6858ffdffff8b       | mov                 byte ptr [ebp - 0x271], 0x8b
            //   c68590fdffff34       | mov                 byte ptr [ebp - 0x270], 0x34
            //   c68591fdffff93       | mov                 byte ptr [ebp - 0x26f], 0x93
            //   c68592fdffff5b       | mov                 byte ptr [ebp - 0x26e], 0x5b

        $sequence_6 = { 03d8 8d441b02 50 56 }
            // n = 4, score = 100
            //   03d8                 | add                 ebx, eax
            //   8d441b02             | lea                 eax, [ebx + ebx + 2]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_7 = { 397d0c 7503 897dfc 6a1b e8???????? 8bf0 59 }
            // n = 7, score = 100
            //   397d0c               | cmp                 dword ptr [ebp + 0xc], edi
            //   7503                 | jne                 5
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   6a1b                 | push                0x1b
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx

        $sequence_8 = { 6685d2 75d4 8d7c5f02 03ff 6a01 57 e8???????? }
            // n = 7, score = 100
            //   6685d2               | test                dx, dx
            //   75d4                 | jne                 0xffffffd6
            //   8d7c5f02             | lea                 edi, [edi + ebx*2 + 2]
            //   03ff                 | add                 edi, edi
            //   6a01                 | push                1
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_9 = { 50 e8???????? 8d9574ffffff 83c40c }
            // n = 4, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d9574ffffff         | lea                 edx, [ebp - 0x8c]
            //   83c40c               | add                 esp, 0xc

    condition:
        7 of them and filesize < 221184
}