rule win_royal_dns_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.royal_dns."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.royal_dns"
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
        $sequence_0 = { c685d8fbffff00 e8???????? 83c40c 6803010000 8d8de1fcffff 6a00 }
            // n = 6, score = 100
            //   c685d8fbffff00       | mov                 byte ptr [ebp - 0x428], 0
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6803010000           | push                0x103
            //   8d8de1fcffff         | lea                 ecx, [ebp - 0x31f]
            //   6a00                 | push                0

        $sequence_1 = { 53 ffd6 8b4dec 51 ffd6 }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   51                   | push                ecx
            //   ffd6                 | call                esi

        $sequence_2 = { 0fb6d9 43 0118 8b85e8faffff }
            // n = 4, score = 100
            //   0fb6d9               | movzx               ebx, cl
            //   43                   | inc                 ebx
            //   0118                 | add                 dword ptr [eax], ebx
            //   8b85e8faffff         | mov                 eax, dword ptr [ebp - 0x518]

        $sequence_3 = { 0fb68070132500 8801 0fb606 0fb65e01 83e003 c1e004 c1eb04 }
            // n = 7, score = 100
            //   0fb68070132500       | movzx               eax, byte ptr [eax + 0x251370]
            //   8801                 | mov                 byte ptr [ecx], al
            //   0fb606               | movzx               eax, byte ptr [esi]
            //   0fb65e01             | movzx               ebx, byte ptr [esi + 1]
            //   83e003               | and                 eax, 3
            //   c1e004               | shl                 eax, 4
            //   c1eb04               | shr                 ebx, 4

        $sequence_4 = { 0fbe8060f62400 83e00f eb02 33c0 }
            // n = 4, score = 100
            //   0fbe8060f62400       | movsx               eax, byte ptr [eax + 0x24f660]
            //   83e00f               | and                 eax, 0xf
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_5 = { 8d85f4fbffff c785dcfaffff10000000 50 eb12 6a00 6a00 6a00 }
            // n = 7, score = 100
            //   8d85f4fbffff         | lea                 eax, [ebp - 0x40c]
            //   c785dcfaffff10000000     | mov    dword ptr [ebp - 0x524], 0x10
            //   50                   | push                eax
            //   eb12                 | jmp                 0x14
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_6 = { 0f82aafeffff 8b45e8 8b4dfc 5f 5e 33cd 5b }
            // n = 7, score = 100
            //   0f82aafeffff         | jb                  0xfffffeb0
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33cd                 | xor                 ecx, ebp
            //   5b                   | pop                 ebx

        $sequence_7 = { ff15???????? 0fb7c8 8d5c0b0c 81fb00040000 7612 83c8ff }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   0fb7c8               | movzx               ecx, ax
            //   8d5c0b0c             | lea                 ebx, [ebx + ecx + 0xc]
            //   81fb00040000         | cmp                 ebx, 0x400
            //   7612                 | jbe                 0x14
            //   83c8ff               | or                  eax, 0xffffffff

        $sequence_8 = { f7f1 8d95f0feffff 68???????? 52 8bf8 }
            // n = 5, score = 100
            //   f7f1                 | div                 ecx
            //   8d95f0feffff         | lea                 edx, [ebp - 0x110]
            //   68????????           |                     
            //   52                   | push                edx
            //   8bf8                 | mov                 edi, eax

        $sequence_9 = { 8dbda0f5ffff 50 f3a5 e8???????? 83c40c b908000000 be???????? }
            // n = 7, score = 100
            //   8dbda0f5ffff         | lea                 edi, [ebp - 0xa60]
            //   50                   | push                eax
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   b908000000           | mov                 ecx, 8
            //   be????????           |                     

    condition:
        7 of them and filesize < 204800
}