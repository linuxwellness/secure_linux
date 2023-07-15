rule win_rhttpctrl_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.rhttpctrl."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rhttpctrl"
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
        $sequence_0 = { c7471400000000 c7470800000000 5f e8???????? }
            // n = 4, score = 100
            //   c7471400000000       | mov                 dword ptr [edi + 0x14], 0
            //   c7470800000000       | mov                 dword ptr [edi + 8], 0
            //   5f                   | pop                 edi
            //   e8????????           |                     

        $sequence_1 = { 83c414 5f 5e 5b 8b4c2418 33cc }
            // n = 6, score = 100
            //   83c414               | add                 esp, 0x14
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   33cc                 | xor                 ecx, esp

        $sequence_2 = { 807c302800 7d3c e8???????? 8b404c 83b8a800000000 750e 8b04bd30424200 }
            // n = 7, score = 100
            //   807c302800           | cmp                 byte ptr [eax + esi + 0x28], 0
            //   7d3c                 | jge                 0x3e
            //   e8????????           |                     
            //   8b404c               | mov                 eax, dword ptr [eax + 0x4c]
            //   83b8a800000000       | cmp                 dword ptr [eax + 0xa8], 0
            //   750e                 | jne                 0x10
            //   8b04bd30424200       | mov                 eax, dword ptr [edi*4 + 0x424230]

        $sequence_3 = { 84c0 740c 8b45e4 e8???????? 8bfc eb2e 8b4de4 }
            // n = 7, score = 100
            //   84c0                 | test                al, al
            //   740c                 | je                  0xe
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   e8????????           |                     
            //   8bfc                 | mov                 edi, esp
            //   eb2e                 | jmp                 0x30
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]

        $sequence_4 = { b9ffffff7f e8???????? 84c0 7473 }
            // n = 4, score = 100
            //   b9ffffff7f           | mov                 ecx, 0x7fffffff
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7473                 | je                  0x75

        $sequence_5 = { ffb5f4feffff 83c62a ffb5f0feffff 56 e8???????? 03b5f4feffff }
            // n = 6, score = 100
            //   ffb5f4feffff         | push                dword ptr [ebp - 0x10c]
            //   83c62a               | add                 esi, 0x2a
            //   ffb5f0feffff         | push                dword ptr [ebp - 0x110]
            //   56                   | push                esi
            //   e8????????           |                     
            //   03b5f4feffff         | add                 esi, dword ptr [ebp - 0x10c]

        $sequence_6 = { ff75e8 ff15???????? 8b4dfc 83c8ff 33cd }
            // n = 5, score = 100
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   ff15????????         |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c8ff               | or                  eax, 0xffffffff
            //   33cd                 | xor                 ecx, ebp

        $sequence_7 = { 50 8d842498000000 50 e8???????? 83cbff 85c0 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8d842498000000       | lea                 eax, [esp + 0x98]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83cbff               | or                  ebx, 0xffffffff
            //   85c0                 | test                eax, eax

        $sequence_8 = { e8???????? 83c408 68???????? ff15???????? ff05???????? 68???????? ff15???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   68????????           |                     
            //   ff15????????         |                     
            //   ff05????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_9 = { e8???????? 6857000780 e8???????? 6805400080 e8???????? 90 1921 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6857000780           | push                0x80070057
            //   e8????????           |                     
            //   6805400080           | push                0x80004005
            //   e8????????           |                     
            //   90                   | nop                 
            //   1921                 | sbb                 dword ptr [ecx], esp

    condition:
        7 of them and filesize < 339968
}