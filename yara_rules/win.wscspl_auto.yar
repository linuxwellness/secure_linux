rule win_wscspl_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.wscspl."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wscspl"
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
        $sequence_0 = { 8b3d???????? 8bf0 a1???????? 83c404 50 57 56 }
            // n = 7, score = 400
            //   8b3d????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   a1????????           |                     
            //   83c404               | add                 esp, 4
            //   50                   | push                eax
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_1 = { c744241c04010000 ff15???????? 85c0 752b }
            // n = 4, score = 400
            //   c744241c04010000     | mov                 dword ptr [esp + 0x1c], 0x104
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   752b                 | jne                 0x2d

        $sequence_2 = { 888c0480030000 40 84c9 75ee 8d842480030000 48 }
            // n = 6, score = 400
            //   888c0480030000       | mov                 byte ptr [esp + eax + 0x380], cl
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75ee                 | jne                 0xfffffff0
            //   8d842480030000       | lea                 eax, [esp + 0x380]
            //   48                   | dec                 eax

        $sequence_3 = { 8b74240c 3bf7 7435 8b3d???????? 8d4900 8b4618 8b4004 }
            // n = 7, score = 400
            //   8b74240c             | mov                 esi, dword ptr [esp + 0xc]
            //   3bf7                 | cmp                 esi, edi
            //   7435                 | je                  0x37
            //   8b3d????????         |                     
            //   8d4900               | lea                 ecx, [ecx]
            //   8b4618               | mov                 eax, dword ptr [esi + 0x18]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]

        $sequence_4 = { 7536 ff15???????? 8bf0 a1???????? 50 }
            // n = 5, score = 400
            //   7536                 | jne                 0x38
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   a1????????           |                     
            //   50                   | push                eax

        $sequence_5 = { 0303 0301 0003 0303 0303 0003 0303 }
            // n = 7, score = 400
            //   0303                 | add                 eax, dword ptr [ebx]
            //   0301                 | add                 eax, dword ptr [ecx]
            //   0003                 | add                 byte ptr [ebx], al
            //   0303                 | add                 eax, dword ptr [ebx]
            //   0303                 | add                 eax, dword ptr [ebx]
            //   0003                 | add                 byte ptr [ebx], al
            //   0303                 | add                 eax, dword ptr [ebx]

        $sequence_6 = { 68???????? 6a00 6a00 c705????????a00f0000 c705????????b80b0000 }
            // n = 5, score = 400
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   c705????????a00f0000     |     
            //   c705????????b80b0000     |     

        $sequence_7 = { 68???????? 68???????? e8???????? 889fe8e24500 }
            // n = 4, score = 400
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   889fe8e24500         | mov                 byte ptr [edi + 0x45e2e8], bl

        $sequence_8 = { a3???????? e8???????? 8b0d???????? 8b3d???????? 51 8bf0 57 }
            // n = 7, score = 400
            //   a3????????           |                     
            //   e8????????           |                     
            //   8b0d????????         |                     
            //   8b3d????????         |                     
            //   51                   | push                ecx
            //   8bf0                 | mov                 esi, eax
            //   57                   | push                edi

        $sequence_9 = { 2bc1 8b4c2448 03f0 8b442444 ba3f3a0000 }
            // n = 5, score = 400
            //   2bc1                 | sub                 eax, ecx
            //   8b4c2448             | mov                 ecx, dword ptr [esp + 0x48]
            //   03f0                 | add                 esi, eax
            //   8b442444             | mov                 eax, dword ptr [esp + 0x44]
            //   ba3f3a0000           | mov                 edx, 0x3a3f

    condition:
        7 of them and filesize < 901120
}