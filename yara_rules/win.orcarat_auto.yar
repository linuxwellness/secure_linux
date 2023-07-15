rule win_orcarat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.orcarat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.orcarat"
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
        $sequence_0 = { 83e103 85c0 f3a4 7411 50 }
            // n = 5, score = 200
            //   83e103               | and                 ecx, 3
            //   85c0                 | test                eax, eax
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   7411                 | je                  0x13
            //   50                   | push                eax

        $sequence_1 = { 85c0 7e29 8b54240c 8b44241c 8b7c2420 2bd0 8b442410 }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   7e29                 | jle                 0x2b
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   8b7c2420             | mov                 edi, dword ptr [esp + 0x20]
            //   2bd0                 | sub                 edx, eax
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]

        $sequence_2 = { 0f84e6000000 8b3d???????? ffd7 898658030000 eb06 }
            // n = 5, score = 200
            //   0f84e6000000         | je                  0xec
            //   8b3d????????         |                     
            //   ffd7                 | call                edi
            //   898658030000         | mov                 dword ptr [esi + 0x358], eax
            //   eb06                 | jmp                 8

        $sequence_3 = { c21000 c7432006000000 6a06 83c30c 56 53 e8???????? }
            // n = 7, score = 200
            //   c21000               | ret                 0x10
            //   c7432006000000       | mov                 dword ptr [ebx + 0x20], 6
            //   6a06                 | push                6
            //   83c30c               | add                 ebx, 0xc
            //   56                   | push                esi
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_4 = { 8d86f8020000 53 8dbef4020000 51 50 57 }
            // n = 6, score = 200
            //   8d86f8020000         | lea                 eax, [esi + 0x2f8]
            //   53                   | push                ebx
            //   8dbef4020000         | lea                 edi, [esi + 0x2f4]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_5 = { e8???????? 85c0 7507 5e 5d }
            // n = 5, score = 200
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_6 = { 0fb6da f68381b6400004 7406 8816 46 }
            // n = 5, score = 200
            //   0fb6da               | movzx               ebx, dl
            //   f68381b6400004       | test                byte ptr [ebx + 0x40b681], 4
            //   7406                 | je                  8
            //   8816                 | mov                 byte ptr [esi], dl
            //   46                   | inc                 esi

        $sequence_7 = { 83e103 f3a4 8dbc2430140000 83c9ff f2ae f7d1 }
            // n = 6, score = 200
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8dbc2430140000       | lea                 edi, [esp + 0x1430]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx

        $sequence_8 = { 49 50 51 52 53 894c2428 ff15???????? }
            // n = 7, score = 200
            //   49                   | dec                 ecx
            //   50                   | push                eax
            //   51                   | push                ecx
            //   52                   | push                edx
            //   53                   | push                ebx
            //   894c2428             | mov                 dword ptr [esp + 0x28], ecx
            //   ff15????????         |                     

        $sequence_9 = { 8b44242c 8d532c 03f0 8bfa }
            // n = 4, score = 200
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   8d532c               | lea                 edx, [ebx + 0x2c]
            //   03f0                 | add                 esi, eax
            //   8bfa                 | mov                 edi, edx

    condition:
        7 of them and filesize < 114688
}