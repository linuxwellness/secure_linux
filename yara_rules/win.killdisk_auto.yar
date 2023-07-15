rule win_killdisk_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-29"
        version = "1"
        description = "Detects win.killdisk."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.killdisk"
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
        $sequence_0 = { 33c0 56 8bf0 89442404 8944240c }
            // n = 5, score = 100
            //   33c0                 | xor                 eax, eax
            //   56                   | push                esi
            //   8bf0                 | mov                 esi, eax
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax

        $sequence_1 = { 83b84896c20100 74f0 83c004 83f870 72ef }
            // n = 5, score = 100
            //   83b84896c20100       | cmp                 dword ptr [eax + 0x1c29648], 0
            //   74f0                 | je                  0xfffffff2
            //   83c004               | add                 eax, 4
            //   83f870               | cmp                 eax, 0x70
            //   72ef                 | jb                  0xfffffff1

        $sequence_2 = { 5d c3 6a05 56 ff15???????? }
            // n = 5, score = 100
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   6a05                 | push                5
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_3 = { 83c40c 8d9424b0000000 8d4c2410 e8???????? 84c0 }
            // n = 5, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8d9424b0000000       | lea                 edx, [esp + 0xb0]
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   e8????????           |                     
            //   84c0                 | test                al, al

        $sequence_4 = { e8???????? 9c c6442408cf 894508 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   9c                   | pushfd              
            //   c6442408cf           | mov                 byte ptr [esp + 8], 0xcf
            //   894508               | mov                 dword ptr [ebp + 8], eax

        $sequence_5 = { 57 8bf1 7479 85ed 7475 }
            // n = 5, score = 100
            //   57                   | push                edi
            //   8bf1                 | mov                 esi, ecx
            //   7479                 | je                  0x7b
            //   85ed                 | test                ebp, ebp
            //   7475                 | je                  0x77

        $sequence_6 = { 897c2408 9c 8d642430 e9???????? ff742404 }
            // n = 5, score = 100
            //   897c2408             | mov                 dword ptr [esp + 8], edi
            //   9c                   | pushfd              
            //   8d642430             | lea                 esp, [esp + 0x30]
            //   e9????????           |                     
            //   ff742404             | push                dword ptr [esp + 4]

        $sequence_7 = { 8b442418 85c0 0f84f6010000 83f8ff 0f84ed010000 85db }
            // n = 6, score = 100
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   85c0                 | test                eax, eax
            //   0f84f6010000         | je                  0x1fc
            //   83f8ff               | cmp                 eax, -1
            //   0f84ed010000         | je                  0x1f3
            //   85db                 | test                ebx, ebx

        $sequence_8 = { 890c02 8b442434 6a00 6a00 8947e4 }
            // n = 5, score = 100
            //   890c02               | mov                 dword ptr [edx + eax], ecx
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8947e4               | mov                 dword ptr [edi - 0x1c], eax

        $sequence_9 = { 080f 872d???????? 0fc1c2 89e2 66d3c9 }
            // n = 5, score = 100
            //   080f                 | or                  byte ptr [edi], cl
            //   872d????????         |                     
            //   0fc1c2               | xadd                edx, eax
            //   89e2                 | mov                 edx, esp
            //   66d3c9               | ror                 cx, cl

        $sequence_10 = { c604243a 9c 8d642434 e9???????? 883424 }
            // n = 5, score = 100
            //   c604243a             | mov                 byte ptr [esp], 0x3a
            //   9c                   | pushfd              
            //   8d642434             | lea                 esp, [esp + 0x34]
            //   e9????????           |                     
            //   883424               | mov                 byte ptr [esp], dh

        $sequence_11 = { d1924dbeb698 760a d035???????? d6 }
            // n = 4, score = 100
            //   d1924dbeb698         | rcl                 dword ptr [edx - 0x674941b3], 1
            //   760a                 | jbe                 0xc
            //   d035????????         |                     
            //   d6                   | salc                

        $sequence_12 = { 8d0412 50 89b114040000 83472401 }
            // n = 4, score = 100
            //   8d0412               | lea                 eax, [edx + edx]
            //   50                   | push                eax
            //   89b114040000         | mov                 dword ptr [ecx + 0x414], esi
            //   83472401             | add                 dword ptr [edi + 0x24], 1

        $sequence_13 = { e9???????? 9c 9c 66894504 }
            // n = 4, score = 100
            //   e9????????           |                     
            //   9c                   | pushfd              
            //   9c                   | pushfd              
            //   66894504             | mov                 word ptr [ebp + 4], ax

        $sequence_14 = { 9c 8f442428 882424 881c24 e8???????? d2cd 80d213 }
            // n = 7, score = 100
            //   9c                   | pushfd              
            //   8f442428             | pop                 dword ptr [esp + 0x28]
            //   882424               | mov                 byte ptr [esp], ah
            //   881c24               | mov                 byte ptr [esp], bl
            //   e8????????           |                     
            //   d2cd                 | ror                 ch, cl
            //   80d213               | adc                 dl, 0x13

        $sequence_15 = { 66ffc6 e8???????? 9c 8f442420 ff3424 ff742424 8f4500 }
            // n = 7, score = 100
            //   66ffc6               | inc                 si
            //   e8????????           |                     
            //   9c                   | pushfd              
            //   8f442420             | pop                 dword ptr [esp + 0x20]
            //   ff3424               | push                dword ptr [esp]
            //   ff742424             | push                dword ptr [esp + 0x24]
            //   8f4500               | pop                 dword ptr [ebp]

    condition:
        7 of them and filesize < 10817536
}