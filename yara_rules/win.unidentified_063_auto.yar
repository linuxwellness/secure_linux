rule win_unidentified_063_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.unidentified_063."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_063"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 8d43cf 83f819 770c 6689b550030000 e9???????? }
            // n = 5, score = 200
            //   8d43cf               | dec                 eax
            //   83f819               | lea                 ecx, [0x194ad]
            //   770c                 | dec                 eax
            //   6689b550030000       | mov                 dword ptr [ebx], ecx
            //   e9????????           |                     

        $sequence_1 = { 7363 488bf3 4c8d35dfc40100 83e63f 488beb 48c1fd06 48c1e606 }
            // n = 7, score = 200
            //   7363                 | dec                 eax
            //   488bf3               | mov                 eax, 0xaaaaaaaa
            //   4c8d35dfc40100       | stosb               byte ptr es:[edi], al
            //   83e63f               | stosb               byte ptr es:[edi], al
            //   488beb               | stosb               byte ptr es:[edi], al
            //   48c1fd06             | or                  cl, byte ptr [eax + 0x3b]
            //   48c1e606             | sal                 byte ptr [edi + 0x51], 1

        $sequence_2 = { e8???????? 4863f8 488d3588800100 488bcb }
            // n = 4, score = 200
            //   e8????????           |                     
            //   4863f8               | mov                 ecx, dword ptr [edi]
            //   488d3588800100       | mov                 dword ptr [ebp - 0x75], eax
            //   488bcb               | lea                 eax, [eax*4 + 0x1f]

        $sequence_3 = { 0f11442478 4c8b4708 488d442470 493bc0 7362 488b07 488d4c2470 }
            // n = 7, score = 200
            //   0f11442478           | dec                 eax
            //   4c8b4708             | arpl                cx, ax
            //   488d442470           | dec                 esp
            //   493bc0               | lea                 ecx, [esp]
            //   7362                 | jge                 0x1c9
            //   488b07               | dec                 ecx
            //   488d4c2470           | or                  ecx, 0xffffff00

        $sequence_4 = { 4885c9 7407 48ff25???????? c3 48894c2408 57 4883ec50 }
            // n = 7, score = 200
            //   4885c9               | je                  0x65c
            //   7407                 | sub                 edx, ecx
            //   48ff25????????       |                     
            //   c3                   | mov                 cl, dl
            //   48894c2408           | dec                 eax
            //   57                   | mov                 edx, eax
            //   4883ec50             | dec                 eax

        $sequence_5 = { 83f801 7518 488b0d???????? 488d05bf5f0100 483bc8 7405 e8???????? }
            // n = 7, score = 200
            //   83f801               | fisttp              dword ptr [eax - 0x77]
            //   7518                 | pop                 esp
            //   488b0d????????       |                     
            //   488d05bf5f0100       | and                 al, 0x50
            //   483bc8               | inc                 ecx
            //   7405                 | cmp                 dword ptr [edx + 8], 2
            //   e8????????           |                     

        $sequence_6 = { 8b8c96d0cd0200 8b534c 33c8 0fb6c1 }
            // n = 4, score = 200
            //   8b8c96d0cd0200       | lea                 eax, [0x14a3a]
            //   8b534c               | dec                 eax
            //   33c8                 | cmp                 dword ptr [edi - 0x10], eax
            //   0fb6c1               | je                  0x2f

        $sequence_7 = { 0f84e7000000 488b0e 483bc8 740e 4885c9 7406 }
            // n = 6, score = 200
            //   0f84e7000000         | mov                 edi, ecx
            //   488b0e               | push                edi
            //   483bc8               | dec                 eax
            //   740e                 | sub                 esp, 0x20
            //   4885c9               | dec                 eax
            //   7406                 | mov                 edi, ecx

        $sequence_8 = { 498bc2 418be9 48c1f806 488d0d708c0100 4183e23f 4903e8 }
            // n = 6, score = 200
            //   498bc2               | dec                 esp
            //   418be9               | lea                 ecx, [0xccea]
            //   48c1f806             | dec                 eax
            //   488d0d708c0100       | sub                 esp, 0x148
            //   4183e23f             | dec                 eax
            //   4903e8               | xor                 eax, esp

        $sequence_9 = { 488d158a5a0200 488bcb e8???????? 85c0 7499 488d157f5a0200 488bcb }
            // n = 7, score = 200
            //   488d158a5a0200       | dec                 eax
            //   488bcb               | lea                 edx, [0x14b87]
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   7499                 | cmp                 dword ptr [eax - 0x10], edx
            //   488d157f5a0200       | dec                 eax
            //   488bcb               | test                eax, eax

    condition:
        7 of them and filesize < 475136
}