rule win_unidentified_003_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.unidentified_003."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_003"
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
        $sequence_0 = { 837df00a 0f8d4f010000 8b45f4 803800 0f8443010000 8d95e0f9ffff }
            // n = 6, score = 100
            //   837df00a             | cmp                 dword ptr [ebp - 0x10], 0xa
            //   0f8d4f010000         | jge                 0x155
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   803800               | cmp                 byte ptr [eax], 0
            //   0f8443010000         | je                  0x149
            //   8d95e0f9ffff         | lea                 edx, [ebp - 0x620]

        $sequence_1 = { 50 8945fc e8???????? 59 59 85c0 7521 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7521                 | jne                 0x23

        $sequence_2 = { 6a0c bb???????? 53 6a01 68???????? 68???????? }
            // n = 6, score = 100
            //   6a0c                 | push                0xc
            //   bb????????           |                     
            //   53                   | push                ebx
            //   6a01                 | push                1
            //   68????????           |                     
            //   68????????           |                     

        $sequence_3 = { 75f5 ff75fc 2bc1 53 d1f8 682321f3af }
            // n = 6, score = 100
            //   75f5                 | jne                 0xfffffff7
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   2bc1                 | sub                 eax, ecx
            //   53                   | push                ebx
            //   d1f8                 | sar                 eax, 1
            //   682321f3af           | push                0xaff32123

        $sequence_4 = { 895dfc 895ddc 895df0 895dec 895df4 895de4 }
            // n = 6, score = 100
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   895ddc               | mov                 dword ptr [ebp - 0x24], ebx
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx

        $sequence_5 = { 893d???????? e9???????? 83bd5cffffff02 0f858a000000 c705????????06000000 eb7e }
            // n = 6, score = 100
            //   893d????????         |                     
            //   e9????????           |                     
            //   83bd5cffffff02       | cmp                 dword ptr [ebp - 0xa4], 2
            //   0f858a000000         | jne                 0x90
            //   c705????????06000000     |     
            //   eb7e                 | jmp                 0x80

        $sequence_6 = { c740101e160900 c740143e160900 eb02 33c0 a3???????? 3bc3 0f84f2000000 }
            // n = 7, score = 100
            //   c740101e160900       | mov                 dword ptr [eax + 0x10], 0x9161e
            //   c740143e160900       | mov                 dword ptr [eax + 0x14], 0x9163e
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   a3????????           |                     
            //   3bc3                 | cmp                 eax, ebx
            //   0f84f2000000         | je                  0xf8

        $sequence_7 = { ff45fc 8b45fc 8145f80c020000 81c718040000 3b45f0 0f8238ffffff eb07 }
            // n = 7, score = 100
            //   ff45fc               | inc                 dword ptr [ebp - 4]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8145f80c020000       | add                 dword ptr [ebp - 8], 0x20c
            //   81c718040000         | add                 edi, 0x418
            //   3b45f0               | cmp                 eax, dword ptr [ebp - 0x10]
            //   0f8238ffffff         | jb                  0xffffff3e
            //   eb07                 | jmp                 9

        $sequence_8 = { 3c25 7404 8807 eb58 }
            // n = 4, score = 100
            //   3c25                 | cmp                 al, 0x25
            //   7404                 | je                  6
            //   8807                 | mov                 byte ptr [edi], al
            //   eb58                 | jmp                 0x5a

        $sequence_9 = { 01460c 8b460c 394604 7420 }
            // n = 4, score = 100
            //   01460c               | add                 dword ptr [esi + 0xc], eax
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   394604               | cmp                 dword ptr [esi + 4], eax
            //   7420                 | je                  0x22

    condition:
        7 of them and filesize < 57344
}