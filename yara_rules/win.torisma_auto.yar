rule win_torisma_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.torisma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.torisma"
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
        $sequence_0 = { 488b542450 8b0482 33c1 8b4c2430 488b542450 89048a ebb5 }
            // n = 7, score = 100
            //   488b542450           | dec                 eax
            //   8b0482               | mov                 eax, dword ptr [esp + 0x50]
            //   33c1                 | mov                 eax, dword ptr [eax + 0x4c]
            //   8b4c2430             | shr                 eax, 0x14
            //   488b542450           | and                 eax, 1
            //   89048a               | dec                 eax
            //   ebb5                 | mov                 ecx, dword ptr [esp + 0x50]

        $sequence_1 = { c1e018 8b4c2430 33c8 8bc1 89442430 }
            // n = 5, score = 100
            //   c1e018               | xor                 eax, ecx
            //   8b4c2430             | dec                 eax
            //   33c8                 | mov                 ecx, dword ptr [esp + 0x50]
            //   8bc1                 | mov                 ecx, dword ptr [ecx + 0x68]
            //   89442430             | shr                 ecx, 0x15

        $sequence_2 = { 0bd1 8bca 898c24e8000000 488b542478 8b520c 488b7c2470 }
            // n = 6, score = 100
            //   0bd1                 | dec                 esp
            //   8bca                 | mov                 dword ptr [esp + 0x18], eax
            //   898c24e8000000       | dec                 eax
            //   488b542478           | mov                 dword ptr [esp + 0x10], edx
            //   8b520c               | dec                 eax
            //   488b7c2470           | mov                 dword ptr [esp + 8], ecx

        $sequence_3 = { 8b942400010000 0bd1 8bca 898c2404010000 488b542478 }
            // n = 5, score = 100
            //   8b942400010000       | dec                 eax
            //   0bd1                 | mov                 edi, dword ptr [eax + 0x18]
            //   8bca                 | xor                 eax, eax
            //   898c2404010000       | mov                 ecx, 0xc
            //   488b542478           | dec                 eax

        $sequence_4 = { 4c8d05a6340100 ba00020000 488b4c2448 e8???????? eb63 }
            // n = 5, score = 100
            //   4c8d05a6340100       | dec                 eax
            //   ba00020000           | sub                 esp, 0xa8
            //   488b4c2448           | dec                 eax
            //   e8????????           |                     
            //   eb63                 | mov                 dword ptr [esp + 0x70], 0xfffffffe

        $sequence_5 = { 7411 488b4c2448 e8???????? 4889442478 eb09 48c744247800000000 488b442478 }
            // n = 7, score = 100
            //   7411                 | dec                 eax
            //   488b4c2448           | mov                 eax, dword ptr [esp + 0x50]
            //   e8????????           |                     
            //   4889442478           | dec                 eax
            //   eb09                 | cmp                 dword ptr [eax], -1
            //   48c744247800000000     | je    0x1c83
            //   488b442478           | inc                 ecx

        $sequence_6 = { 488b17 488b4c2468 e8???????? 488b842420010000 488b00 488b8c2420010000 488b09 }
            // n = 7, score = 100
            //   488b17               | je                  0x4d4
            //   488b4c2468           | dec                 eax
            //   e8????????           |                     
            //   488b842420010000     | mov                 eax, dword ptr [esp + 0x48]
            //   488b00               | dec                 eax
            //   488b8c2420010000     | mov                 dword ptr [esp + 0xe0], eax
            //   488b09               | dec                 eax

        $sequence_7 = { 8bc1 8bc0 488b4c2438 4803c8 488bc1 }
            // n = 5, score = 100
            //   8bc1                 | je                  0x200f
            //   8bc0                 | mov                 edx, 1
            //   488b4c2438           | dec                 eax
            //   4803c8               | mov                 eax, dword ptr [esp + 0x70]
            //   488bc1               | dec                 eax

        $sequence_8 = { 33c1 488b4c2450 8b4968 c1e90f 83e101 33c1 488b4c2450 }
            // n = 7, score = 100
            //   33c1                 | mov                 edx, dword ptr [ecx]
            //   488b4c2450           | dec                 eax
            //   8b4968               | mov                 eax, dword ptr [esp + 0x120]
            //   c1e90f               | dec                 eax
            //   83e101               | mov                 eax, dword ptr [eax]
            //   33c1                 | dec                 eax
            //   488b4c2450           | mov                 ecx, dword ptr [esp + 0x120]

        $sequence_9 = { 488b842480000000 488b00 c7404000000000 488b842480000000 488b00 c7403c00000000 }
            // n = 6, score = 100
            //   488b842480000000     | mov                 ecx, dword ptr [esp + 0x30]
            //   488b00               | shr                 ecx, 7
            //   c7404000000000       | and                 ecx, 1
            //   488b842480000000     | xor                 eax, ecx
            //   488b00               | dec                 eax
            //   c7403c00000000       | mov                 ecx, dword ptr [esp + 0x50]

    condition:
        7 of them and filesize < 322560
}