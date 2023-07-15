rule win_kagent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.kagent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kagent"
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
        $sequence_0 = { 32c0 c3 81ffffffff1f 760a 68???????? e8???????? }
            // n = 6, score = 400
            //   32c0                 | xor                 al, al
            //   c3                   | ret                 
            //   81ffffffff1f         | cmp                 edi, 0x1fffffff
            //   760a                 | jbe                 0xc
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_1 = { 740c 50 e8???????? 83c404 897d0c }
            // n = 5, score = 400
            //   740c                 | je                  0xe
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   897d0c               | mov                 dword ptr [ebp + 0xc], edi

        $sequence_2 = { e8???????? 83c408 8d7dac c645fc0d e8???????? c645fc0a }
            // n = 6, score = 400
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8d7dac               | lea                 edi, [ebp - 0x54]
            //   c645fc0d             | mov                 byte ptr [ebp - 4], 0xd
            //   e8????????           |                     
            //   c645fc0a             | mov                 byte ptr [ebp - 4], 0xa

        $sequence_3 = { e8???????? 33c9 8945e0 c645e401 895ddc 83c404 668908 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   c645e401             | mov                 byte ptr [ebp - 0x1c], 1
            //   895ddc               | mov                 dword ptr [ebp - 0x24], ebx
            //   83c404               | add                 esp, 4
            //   668908               | mov                 word ptr [eax], cx

        $sequence_4 = { e8???????? 83c404 c7868c00000000000000 8b8680000000 85c0 7413 50 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c7868c00000000000000     | mov    dword ptr [esi + 0x8c], 0
            //   8b8680000000         | mov                 eax, dword ptr [esi + 0x80]
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15
            //   50                   | push                eax

        $sequence_5 = { 884608 33c9 b801000000 ba02000000 f7e2 0f90c1 f7d9 }
            // n = 7, score = 400
            //   884608               | mov                 byte ptr [esi + 8], al
            //   33c9                 | xor                 ecx, ecx
            //   b801000000           | mov                 eax, 1
            //   ba02000000           | mov                 edx, 2
            //   f7e2                 | mul                 edx
            //   0f90c1               | seto                cl
            //   f7d9                 | neg                 ecx

        $sequence_6 = { 8945fc 53 56 57 8b7d08 8d850cecffff 50 }
            // n = 7, score = 400
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8d850cecffff         | lea                 eax, [ebp - 0x13f4]
            //   50                   | push                eax

        $sequence_7 = { 8b00 8945ec 3bd1 7424 8b4a04 85c9 741d }
            // n = 7, score = 400
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   3bd1                 | cmp                 edx, ecx
            //   7424                 | je                  0x26
            //   8b4a04               | mov                 ecx, dword ptr [edx + 4]
            //   85c9                 | test                ecx, ecx
            //   741d                 | je                  0x1f

        $sequence_8 = { 3bc3 0f9fc2 8986d0000000 8896cd000000 c745fcffffffff 3bfb }
            // n = 6, score = 400
            //   3bc3                 | cmp                 eax, ebx
            //   0f9fc2               | setg                dl
            //   8986d0000000         | mov                 dword ptr [esi + 0xd0], eax
            //   8896cd000000         | mov                 byte ptr [esi + 0xcd], dl
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   3bfb                 | cmp                 edi, ebx

        $sequence_9 = { 6a00 8bf0 6a00 51 8975e8 e8???????? 8d5601 }
            // n = 7, score = 400
            //   6a00                 | push                0
            //   8bf0                 | mov                 esi, eax
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   8975e8               | mov                 dword ptr [ebp - 0x18], esi
            //   e8????????           |                     
            //   8d5601               | lea                 edx, [esi + 1]

    condition:
        7 of them and filesize < 4972544
}