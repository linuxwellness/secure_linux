rule win_ironhalo_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.ironhalo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ironhalo"
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
        $sequence_0 = { 8d4c2424 51 e8???????? 83c404 eb0b }
            // n = 5, score = 200
            //   8d4c2424             | lea                 ecx, [esp + 0x24]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   eb0b                 | jmp                 0xd

        $sequence_1 = { 8b55fc 8a9250ca4000 089021cf4000 40 3bc7 }
            // n = 5, score = 200
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8a9250ca4000         | mov                 dl, byte ptr [edx + 0x40ca50]
            //   089021cf4000         | or                  byte ptr [eax + 0x40cf21], dl
            //   40                   | inc                 eax
            //   3bc7                 | cmp                 eax, edi

        $sequence_2 = { c1f804 83f807 8945c4 0f87e9060000 ff24854a364000 }
            // n = 5, score = 200
            //   c1f804               | sar                 eax, 4
            //   83f807               | cmp                 eax, 7
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   0f87e9060000         | ja                  0x6ef
            //   ff24854a364000       | jmp                 dword ptr [eax*4 + 0x40364a]

        $sequence_3 = { 83f908 7229 f3a5 ff2495286d4000 8bc7 ba03000000 }
            // n = 6, score = 200
            //   83f908               | cmp                 ecx, 8
            //   7229                 | jb                  0x2b
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff2495286d4000       | jmp                 dword ptr [edx*4 + 0x406d28]
            //   8bc7                 | mov                 eax, edi
            //   ba03000000           | mov                 edx, 3

        $sequence_4 = { 8bf1 c1e603 3b9688c24000 0f851c010000 a1???????? 83f801 }
            // n = 6, score = 200
            //   8bf1                 | mov                 esi, ecx
            //   c1e603               | shl                 esi, 3
            //   3b9688c24000         | cmp                 edx, dword ptr [esi + 0x40c288]
            //   0f851c010000         | jne                 0x122
            //   a1????????           |                     
            //   83f801               | cmp                 eax, 1

        $sequence_5 = { 8b7c2410 381f 7502 8ac2 8b7c2410 fec2 47 }
            // n = 7, score = 200
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]
            //   381f                 | cmp                 byte ptr [edi], bl
            //   7502                 | jne                 4
            //   8ac2                 | mov                 al, dl
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]
            //   fec2                 | inc                 dl
            //   47                   | inc                 edi

        $sequence_6 = { 8b742414 33c9 33ed 8a06 57 84c0 0f84e1000000 }
            // n = 7, score = 200
            //   8b742414             | mov                 esi, dword ptr [esp + 0x14]
            //   33c9                 | xor                 ecx, ecx
            //   33ed                 | xor                 ebp, ebp
            //   8a06                 | mov                 al, byte ptr [esi]
            //   57                   | push                edi
            //   84c0                 | test                al, al
            //   0f84e1000000         | je                  0xe7

        $sequence_7 = { ffd6 8d442460 68???????? 50 ffd6 }
            // n = 5, score = 200
            //   ffd6                 | call                esi
            //   8d442460             | lea                 eax, [esp + 0x60]
            //   68????????           |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_8 = { 8a5c241a 8a542419 c0eb02 80e30f }
            // n = 4, score = 200
            //   8a5c241a             | mov                 bl, byte ptr [esp + 0x1a]
            //   8a542419             | mov                 dl, byte ptr [esp + 0x19]
            //   c0eb02               | shr                 bl, 2
            //   80e30f               | and                 bl, 0xf

        $sequence_9 = { c3 8bc8 83e01f c1f905 8b0c8d60e04000 }
            // n = 5, score = 200
            //   c3                   | ret                 
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d60e04000       | mov                 ecx, dword ptr [ecx*4 + 0x40e060]

    condition:
        7 of them and filesize < 131072
}