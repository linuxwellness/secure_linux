rule win_oni_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.oni."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oni"
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
        $sequence_0 = { 8bf1 ff15???????? 85c0 7507 50 ff15???????? 8d45f4 }
            // n = 7, score = 200
            //   8bf1                 | mov                 esi, ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d45f4               | lea                 eax, [ebp - 0xc]

        $sequence_1 = { 8b4048 f00fc118 4b 7515 8b45fc 81784878764300 7409 }
            // n = 7, score = 200
            //   8b4048               | mov                 eax, dword ptr [eax + 0x48]
            //   f00fc118             | lock xadd           dword ptr [eax], ebx
            //   4b                   | dec                 ebx
            //   7515                 | jne                 0x17
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   81784878764300       | cmp                 dword ptr [eax + 0x48], 0x437678
            //   7409                 | je                  0xb

        $sequence_2 = { 7404 8b06 8901 4a 8955e8 83c104 894de4 }
            // n = 7, score = 200
            //   7404                 | je                  6
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   4a                   | dec                 edx
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   83c104               | add                 ecx, 4
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx

        $sequence_3 = { 83c801 eb02 33c0 5e 85c0 7510 }
            // n = 6, score = 200
            //   83c801               | or                  eax, 1
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax
            //   7510                 | jne                 0x12

        $sequence_4 = { 2bc8 8d040a 33d2 f7f7 8b4dec 8b7df4 }
            // n = 6, score = 200
            //   2bc8                 | sub                 ecx, eax
            //   8d040a               | lea                 eax, [edx + ecx]
            //   33d2                 | xor                 edx, edx
            //   f7f7                 | div                 edi
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]

        $sequence_5 = { 51 52 8d4de0 e8???????? 83ec18 8d85b0feffff 8bcc }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   52                   | push                edx
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   e8????????           |                     
            //   83ec18               | sub                 esp, 0x18
            //   8d85b0feffff         | lea                 eax, [ebp - 0x150]
            //   8bcc                 | mov                 ecx, esp

        $sequence_6 = { 51 e8???????? 83c404 8b4dfc 8a45cb 33cd }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8a45cb               | mov                 al, byte ptr [ebp - 0x35]
            //   33cd                 | xor                 ecx, ebp

        $sequence_7 = { 83b8a800000000 7512 8b04bd90884300 807c302900 7504 32c0 eb1a }
            // n = 7, score = 200
            //   83b8a800000000       | cmp                 dword ptr [eax + 0xa8], 0
            //   7512                 | jne                 0x14
            //   8b04bd90884300       | mov                 eax, dword ptr [edi*4 + 0x438890]
            //   807c302900           | cmp                 byte ptr [eax + esi + 0x29], 0
            //   7504                 | jne                 6
            //   32c0                 | xor                 al, al
            //   eb1a                 | jmp                 0x1c

        $sequence_8 = { 7523 8b493c 85c9 7408 e8???????? 0f1f00 8b06 }
            // n = 7, score = 200
            //   7523                 | jne                 0x25
            //   8b493c               | mov                 ecx, dword ptr [ecx + 0x3c]
            //   85c9                 | test                ecx, ecx
            //   7408                 | je                  0xa
            //   e8????????           |                     
            //   0f1f00               | nop                 dword ptr [eax]
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_9 = { 8d0d00c04200 ba1d000000 e9???????? 833d????????00 0f85fc960000 }
            // n = 5, score = 200
            //   8d0d00c04200         | lea                 ecx, [0x42c000]
            //   ba1d000000           | mov                 edx, 0x1d
            //   e9????????           |                     
            //   833d????????00       |                     
            //   0f85fc960000         | jne                 0x9702

    condition:
        7 of them and filesize < 499712
}