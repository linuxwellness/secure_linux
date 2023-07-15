rule win_termite_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.termite."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.termite"
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
        $sequence_0 = { ffd0 8b4508 8b4010 8b5510 891424 ffd0 8b55f4 }
            // n = 7, score = 200
            //   ffd0                 | call                eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4010               | mov                 eax, dword ptr [eax + 0x10]
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   891424               | mov                 dword ptr [esp], edx
            //   ffd0                 | call                eax
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]

        $sequence_1 = { 6bd074 8b45f0 01d0 c7403c01000000 8345f401 837df463 0f8e71ffffff }
            // n = 7, score = 200
            //   6bd074               | imul                edx, eax, 0x74
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   01d0                 | add                 eax, edx
            //   c7403c01000000       | mov                 dword ptr [eax + 0x3c], 1
            //   8345f401             | add                 dword ptr [ebp - 0xc], 1
            //   837df463             | cmp                 dword ptr [ebp - 0xc], 0x63
            //   0f8e71ffffff         | jle                 0xffffff77

        $sequence_2 = { 8d4201 85c9 a3???????? 7422 8b45c8 c1e004 }
            // n = 6, score = 200
            //   8d4201               | lea                 eax, [edx + 1]
            //   85c9                 | test                ecx, ecx
            //   a3????????           |                     
            //   7422                 | je                  0x24
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   c1e004               | shl                 eax, 4

        $sequence_3 = { eb9f a1???????? 85c0 0f8566010000 8b7514 0fb606 3c2d }
            // n = 7, score = 200
            //   eb9f                 | jmp                 0xffffffa1
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8566010000         | jne                 0x16c
            //   8b7514               | mov                 esi, dword ptr [ebp + 0x14]
            //   0fb606               | movzx               eax, byte ptr [esi]
            //   3c2d                 | cmp                 al, 0x2d

        $sequence_4 = { 7f0a 83f805 741c e9???????? 83f807 0f84de000000 83f808 }
            // n = 7, score = 200
            //   7f0a                 | jg                  0xc
            //   83f805               | cmp                 eax, 5
            //   741c                 | je                  0x1e
            //   e9????????           |                     
            //   83f807               | cmp                 eax, 7
            //   0f84de000000         | je                  0xe4
            //   83f808               | cmp                 eax, 8

        $sequence_5 = { 01d0 c1e002 05???????? c7400801000000 a1???????? }
            // n = 5, score = 200
            //   01d0                 | add                 eax, edx
            //   c1e002               | shl                 eax, 2
            //   05????????           |                     
            //   c7400801000000       | mov                 dword ptr [eax + 8], 1
            //   a1????????           |                     

        $sequence_6 = { 83ec28 e8???????? 8945f4 8b4508 89442408 8b4510 89442404 }
            // n = 7, score = 200
            //   83ec28               | sub                 esp, 0x28
            //   e8????????           |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   89442404             | mov                 dword ptr [esp + 4], eax

        $sequence_7 = { 8b5514 895008 8b4508 c7400cffffffff 8b4508 c74010ffffffff 8b4508 }
            // n = 7, score = 200
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
            //   895008               | mov                 dword ptr [eax + 8], edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   c7400cffffffff       | mov                 dword ptr [eax + 0xc], 0xffffffff
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   c74010ffffffff       | mov                 dword ptr [eax + 0x10], 0xffffffff
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_8 = { 8b11 0f95c3 833d????????00 8d5c9b3a 7454 837d0801 8b35???????? }
            // n = 7, score = 200
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   0f95c3               | setne               bl
            //   833d????????00       |                     
            //   8d5c9b3a             | lea                 ebx, [ebx + ebx*4 + 0x3a]
            //   7454                 | je                  0x56
            //   837d0801             | cmp                 dword ptr [ebp + 8], 1
            //   8b35????????         |                     

        $sequence_9 = { 3b45f4 7fb4 b800000000 c9 c3 }
            // n = 5, score = 200
            //   3b45f4               | cmp                 eax, dword ptr [ebp - 0xc]
            //   7fb4                 | jg                  0xffffffb6
            //   b800000000           | mov                 eax, 0
            //   c9                   | leave               
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 312320
}