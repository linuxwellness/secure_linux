rule win_nosu_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.nosu."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nosu"
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
        $sequence_0 = { 51 8d44241c 8bf9 50 8d442464 50 51 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   8bf9                 | mov                 edi, ecx
            //   50                   | push                eax
            //   8d442464             | lea                 eax, [esp + 0x64]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_1 = { 50 8d442434 50 8d442468 50 33c0 6a03 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d442434             | lea                 eax, [esp + 0x34]
            //   50                   | push                eax
            //   8d442468             | lea                 eax, [esp + 0x68]
            //   50                   | push                eax
            //   33c0                 | xor                 eax, eax
            //   6a03                 | push                3

        $sequence_2 = { 83780404 7406 83780403 7507 8bc8 e9???????? 33c0 }
            // n = 7, score = 100
            //   83780404             | cmp                 dword ptr [eax + 4], 4
            //   7406                 | je                  8
            //   83780403             | cmp                 dword ptr [eax + 4], 3
            //   7507                 | jne                 9
            //   8bc8                 | mov                 ecx, eax
            //   e9????????           |                     
            //   33c0                 | xor                 eax, eax

        $sequence_3 = { 83ec18 53 55 8b6c2428 33c0 56 57 }
            // n = 7, score = 100
            //   83ec18               | sub                 esp, 0x18
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   8b6c2428             | mov                 ebp, dword ptr [esp + 0x28]
            //   33c0                 | xor                 eax, eax
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_4 = { e8???????? 8d9748740300 8d4c2418 e8???????? 8d9788320300 8d4c2418 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d9748740300         | lea                 edx, [edi + 0x37448]
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   e8????????           |                     
            //   8d9788320300         | lea                 edx, [edi + 0x33288]
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   e8????????           |                     

        $sequence_5 = { 8b742414 8be9 57 8bce 8bfa e8???????? 8b5c2414 }
            // n = 7, score = 100
            //   8b742414             | mov                 esi, dword ptr [esp + 0x14]
            //   8be9                 | mov                 ebp, ecx
            //   57                   | push                edi
            //   8bce                 | mov                 ecx, esi
            //   8bfa                 | mov                 edi, edx
            //   e8????????           |                     
            //   8b5c2414             | mov                 ebx, dword ptr [esp + 0x14]

        $sequence_6 = { 8b4c2414 33d2 81c670010000 81c770010000 83e901 894c2414 75ba }
            // n = 7, score = 100
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   33d2                 | xor                 edx, edx
            //   81c670010000         | add                 esi, 0x170
            //   81c770010000         | add                 edi, 0x170
            //   83e901               | sub                 ecx, 1
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx
            //   75ba                 | jne                 0xffffffbc

        $sequence_7 = { 0f45c8 51 ff742430 8bcb 52 8b542448 e8???????? }
            // n = 7, score = 100
            //   0f45c8               | cmovne              ecx, eax
            //   51                   | push                ecx
            //   ff742430             | push                dword ptr [esp + 0x30]
            //   8bcb                 | mov                 ecx, ebx
            //   52                   | push                edx
            //   8b542448             | mov                 edx, dword ptr [esp + 0x48]
            //   e8????????           |                     

        $sequence_8 = { 03d0 89442410 8b470c 83e920 83d800 39442418 7c17 }
            // n = 7, score = 100
            //   03d0                 | add                 edx, eax
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]
            //   83e920               | sub                 ecx, 0x20
            //   83d800               | sbb                 eax, 0
            //   39442418             | cmp                 dword ptr [esp + 0x18], eax
            //   7c17                 | jl                  0x19

        $sequence_9 = { 85c0 0f8478010000 ba00080000 8d4c2470 e8???????? 85c0 0f8462010000 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   0f8478010000         | je                  0x17e
            //   ba00080000           | mov                 edx, 0x800
            //   8d4c2470             | lea                 ecx, [esp + 0x70]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8462010000         | je                  0x168

    condition:
        7 of them and filesize < 513024
}