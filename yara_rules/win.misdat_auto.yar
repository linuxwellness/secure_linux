rule win_misdat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.misdat"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
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
        $sequence_0 = { 8b8568fdffff e8???????? 50 e8???????? eb1b ba???????? }
            // n = 6, score = 200
            //   8b8568fdffff         | mov                 eax, dword ptr [ebp - 0x298]
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   eb1b                 | jmp                 0x1d
            //   ba????????           |                     

        $sequence_1 = { 8d45f0 50 8b45fc e8???????? 50 6802000080 e8???????? }
            // n = 7, score = 200
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   50                   | push                eax
            //   6802000080           | push                0x80000002
            //   e8????????           |                     

        $sequence_2 = { 8b15???????? e8???????? 8b45f0 8d55f4 e8???????? ff75f4 }
            // n = 6, score = 200
            //   8b15????????         |                     
            //   e8????????           |                     
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8d55f4               | lea                 edx, [ebp - 0xc]
            //   e8????????           |                     
            //   ff75f4               | push                dword ptr [ebp - 0xc]

        $sequence_3 = { 57 e8???????? 890424 8bd4 }
            // n = 4, score = 200
            //   57                   | push                edi
            //   e8????????           |                     
            //   890424               | mov                 dword ptr [esp], eax
            //   8bd4                 | mov                 edx, esp

        $sequence_4 = { 8b45f8 e8???????? e9???????? 8d8d54fdffff ba???????? 8b45f8 e8???????? }
            // n = 7, score = 200
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   e9????????           |                     
            //   8d8d54fdffff         | lea                 ecx, [ebp - 0x2ac]
            //   ba????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   e8????????           |                     

        $sequence_5 = { 03d1 8a92cce04000 52 5a 88543d02 8a541e02 }
            // n = 6, score = 200
            //   03d1                 | add                 edx, ecx
            //   8a92cce04000         | mov                 dl, byte ptr [edx + 0x40e0cc]
            //   52                   | push                edx
            //   5a                   | pop                 edx
            //   88543d02             | mov                 byte ptr [ebp + edi + 2], dl
            //   8a541e02             | mov                 dl, byte ptr [esi + ebx + 2]

        $sequence_6 = { 8d442410 50 8d442410 50 6a00 6a00 56 }
            // n = 7, score = 200
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   56                   | push                esi

        $sequence_7 = { 741b 56 8b45f4 e8???????? 8bc8 83e902 ba01000000 }
            // n = 7, score = 200
            //   741b                 | je                  0x1d
            //   56                   | push                esi
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   83e902               | sub                 ecx, 2
            //   ba01000000           | mov                 edx, 1

        $sequence_8 = { 8bd0 8d45d4 e8???????? 8b45d4 5a }
            // n = 5, score = 200
            //   8bd0                 | mov                 edx, eax
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   e8????????           |                     
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   5a                   | pop                 edx

        $sequence_9 = { 8b45f0 8d55f4 e8???????? ff75f4 8d45e8 }
            // n = 5, score = 200
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8d55f4               | lea                 edx, [ebp - 0xc]
            //   e8????????           |                     
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   8d45e8               | lea                 eax, [ebp - 0x18]

    condition:
        7 of them and filesize < 180224
}