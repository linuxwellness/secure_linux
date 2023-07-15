rule win_shadowpad_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.shadowpad."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shadowpad"
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
        $sequence_0 = { 84c9 7409 43 8a0c18 80f92e 75f3 }
            // n = 6, score = 200
            //   84c9                 | test                cl, cl
            //   7409                 | je                  0xb
            //   43                   | inc                 ebx
            //   8a0c18               | mov                 cl, byte ptr [eax + ebx]
            //   80f92e               | cmp                 cl, 0x2e
            //   75f3                 | jne                 0xfffffff5

        $sequence_1 = { 750c 891e 395e08 7e03 895e08 33c0 }
            // n = 6, score = 200
            //   750c                 | jne                 0xe
            //   891e                 | mov                 dword ptr [esi], ebx
            //   395e08               | cmp                 dword ptr [esi + 8], ebx
            //   7e03                 | jle                 5
            //   895e08               | mov                 dword ptr [esi + 8], ebx
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 895df4 895df0 885df8 e8???????? 8d45f8 }
            // n = 5, score = 200
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   885df8               | mov                 byte ptr [ebp - 8], bl
            //   e8????????           |                     
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_3 = { 6a00 8bf0 e8???????? 53 50 ff15???????? }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_4 = { 8975dc 8975e4 8975e0 e8???????? ff75e4 8b7dd8 8b4508 }
            // n = 7, score = 200
            //   8975dc               | mov                 dword ptr [ebp - 0x24], esi
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   e8????????           |                     
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   8b7dd8               | mov                 edi, dword ptr [ebp - 0x28]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_5 = { 53 8d85dcfbffff 50 889ddffbffff }
            // n = 4, score = 200
            //   53                   | push                ebx
            //   8d85dcfbffff         | lea                 eax, [ebp - 0x424]
            //   50                   | push                eax
            //   889ddffbffff         | mov                 byte ptr [ebp - 0x421], bl

        $sequence_6 = { c3 55 8bec 83ec10 56 33c9 33f6 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   56                   | push                esi
            //   33c9                 | xor                 ecx, ecx
            //   33f6                 | xor                 esi, esi

        $sequence_7 = { e8???????? 57 8d4c2410 51 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   57                   | push                edi
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   51                   | push                ecx

        $sequence_8 = { 8bfe 8d45e8 895de8 895dec 895df4 895df0 885df8 }
            // n = 7, score = 200
            //   8bfe                 | mov                 edi, esi
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   895de8               | mov                 dword ptr [ebp - 0x18], ebx
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   885df8               | mov                 byte ptr [ebp - 8], bl

        $sequence_9 = { 51 8d45e0 e8???????? 8b06 }
            // n = 4, score = 200
            //   51                   | push                ecx
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   e8????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]

    condition:
        7 of them and filesize < 188416
}