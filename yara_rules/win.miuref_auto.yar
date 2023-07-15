rule win_miuref_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.miuref."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.miuref"
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
        $sequence_0 = { e8???????? 03f6 56 8bf8 53 57 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   03f6                 | add                 esi, esi
            //   56                   | push                esi
            //   8bf8                 | mov                 edi, eax
            //   53                   | push                ebx
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_1 = { 8d45f4 50 ff7510 ff750c 56 ff15???????? 6a04 }
            // n = 7, score = 200
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   ff15????????         |                     
            //   6a04                 | push                4

        $sequence_2 = { 8365fc00 85c0 7417 8b08 8d55fc 52 ff750c }
            // n = 7, score = 200
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   85c0                 | test                eax, eax
            //   7417                 | je                  0x19
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8d55fc               | lea                 edx, [ebp - 4]
            //   52                   | push                edx
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_3 = { 7551 ff15???????? 83f87a 7546 56 ff75fc 53 }
            // n = 7, score = 200
            //   7551                 | jne                 0x53
            //   ff15????????         |                     
            //   83f87a               | cmp                 eax, 0x7a
            //   7546                 | jne                 0x48
            //   56                   | push                esi
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   53                   | push                ebx

        $sequence_4 = { 8bec ff7514 ff7510 ff7510 ff750c ff7508 68bc010000 }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   68bc010000           | push                0x1bc

        $sequence_5 = { c3 55 8bec 8b4d08 85c9 7432 8b4124 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   85c9                 | test                ecx, ecx
            //   7432                 | je                  0x34
            //   8b4124               | mov                 eax, dword ptr [ecx + 0x24]

        $sequence_6 = { eb99 8b0d???????? 83c106 57 51 8b4e10 8b09 }
            // n = 7, score = 200
            //   eb99                 | jmp                 0xffffff9b
            //   8b0d????????         |                     
            //   83c106               | add                 ecx, 6
            //   57                   | push                edi
            //   51                   | push                ecx
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   8b09                 | mov                 ecx, dword ptr [ecx]

        $sequence_7 = { 7516 8b4608 8d0c88 8b39 c1e202 8b0402 }
            // n = 6, score = 200
            //   7516                 | jne                 0x18
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   8d0c88               | lea                 ecx, [eax + ecx*4]
            //   8b39                 | mov                 edi, dword ptr [ecx]
            //   c1e202               | shl                 edx, 2
            //   8b0402               | mov                 eax, dword ptr [edx + eax]

        $sequence_8 = { 8d55e0 52 57 57 53 50 ff5118 }
            // n = 7, score = 200
            //   8d55e0               | lea                 edx, [ebp - 0x20]
            //   52                   | push                edx
            //   57                   | push                edi
            //   57                   | push                edi
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ff5118               | call                dword ptr [ecx + 0x18]

        $sequence_9 = { 03c6 50 e8???????? 56 8d45f0 50 a1???????? }
            // n = 7, score = 200
            //   03c6                 | add                 eax, esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   56                   | push                esi
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   a1????????           |                     

    condition:
        7 of them and filesize < 180224
}