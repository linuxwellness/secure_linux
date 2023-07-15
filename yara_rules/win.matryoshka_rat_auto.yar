rule win_matryoshka_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.matryoshka_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matryoshka_rat"
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
        $sequence_0 = { c3 b06f c3 b063 c3 }
            // n = 5, score = 400
            //   c3                   | ret                 
            //   b06f                 | mov                 al, 0x6f
            //   c3                   | ret                 
            //   b063                 | mov                 al, 0x63
            //   c3                   | ret                 

        $sequence_1 = { b037 c3 b073 c3 }
            // n = 4, score = 400
            //   b037                 | mov                 al, 0x37
            //   c3                   | ret                 
            //   b073                 | mov                 al, 0x73
            //   c3                   | ret                 

        $sequence_2 = { 8b4620 ff7628 8d0488 50 }
            // n = 4, score = 200
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   ff7628               | push                dword ptr [esi + 0x28]
            //   8d0488               | lea                 eax, [eax + ecx*4]
            //   50                   | push                eax

        $sequence_3 = { 7435 488d0d8ee40400 e8???????? 488b4e08 4c8d4c2430 }
            // n = 5, score = 200
            //   7435                 | je                  0x37
            //   488d0d8ee40400       | dec                 eax
            //   e8????????           |                     
            //   488b4e08             | lea                 ecx, [0x4e48e]
            //   4c8d4c2430           | dec                 eax

        $sequence_4 = { 8b4620 83c404 40 894610 }
            // n = 4, score = 200
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   83c404               | add                 esp, 4
            //   40                   | inc                 eax
            //   894610               | mov                 dword ptr [esi + 0x10], eax

        $sequence_5 = { 7436 0fb74746 ffc6 4883c328 }
            // n = 4, score = 200
            //   7436                 | je                  0x32
            //   0fb74746             | sub                 ecx, 1
            //   ffc6                 | je                  0x2f
            //   4883c328             | sub                 ecx, 1

        $sequence_6 = { 7435 b958020000 e8???????? 48894708 }
            // n = 4, score = 200
            //   7435                 | je                  0x2f
            //   b958020000           | je                  0x37
            //   e8????????           |                     
            //   48894708             | sub                 ecx, 1

        $sequence_7 = { 8b4620 891488 41 3b4e64 }
            // n = 4, score = 200
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   891488               | mov                 dword ptr [eax + ecx*4], edx
            //   41                   | inc                 ecx
            //   3b4e64               | cmp                 ecx, dword ptr [esi + 0x64]

        $sequence_8 = { 8b4620 8d1490 e8???????? 83c404 }
            // n = 4, score = 200
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   8d1490               | lea                 edx, [eax + edx*4]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_9 = { 8b4624 57 8b7e18 2b7e20 57 }
            // n = 5, score = 200
            //   8b4624               | mov                 eax, dword ptr [esi + 0x24]
            //   57                   | push                edi
            //   8b7e18               | mov                 edi, dword ptr [esi + 0x18]
            //   2b7e20               | sub                 edi, dword ptr [esi + 0x20]
            //   57                   | push                edi

        $sequence_10 = { 7435 4c8b4128 4d85c0 742c }
            // n = 4, score = 200
            //   7435                 | and                 dword ptr [esp + 0x20], 0
            //   4c8b4128             | je                  0x37
            //   4d85c0               | dec                 eax
            //   742c                 | lea                 ecx, [0x4e48e]

        $sequence_11 = { 8b4620 894718 8b4660 89471c }
            // n = 4, score = 200
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   894718               | mov                 dword ptr [edi + 0x18], eax
            //   8b4660               | mov                 eax, dword ptr [esi + 0x60]
            //   89471c               | mov                 dword ptr [edi + 0x1c], eax

        $sequence_12 = { 7435 83e901 742d 83e901 }
            // n = 4, score = 200
            //   7435                 | test                eax, eax
            //   83e901               | je                  0x35
            //   742d                 | mov                 dword ptr [ecx + 0x1c], eax
            //   83e901               | je                  0x37

        $sequence_13 = { 7436 33c0 48897c2468 48894608 }
            // n = 4, score = 200
            //   7436                 | mov                 ecx, 0x258
            //   33c0                 | dec                 eax
            //   48897c2468           | mov                 dword ptr [edi + 8], eax
            //   48894608             | dec                 eax

    condition:
        7 of them and filesize < 843776
}