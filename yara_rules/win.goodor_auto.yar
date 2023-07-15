rule win_goodor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.goodor"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
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
        $sequence_0 = { e8???????? 0f0b 8b842458010000 890424 8d0d451b6000 894c2404 c74424080a000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   0f0b                 | ud2                 
            //   8b842458010000       | mov                 eax, dword ptr [esp + 0x158]
            //   890424               | mov                 dword ptr [esp], eax
            //   8d0d451b6000         | lea                 ecx, [0x601b45]
            //   894c2404             | mov                 dword ptr [esp + 4], ecx
            //   c74424080a000000     | mov                 dword ptr [esp + 8], 0xa

        $sequence_1 = { 8d2de07d5c00 892c24 89442404 897c2408 894c240c 89742410 e8???????? }
            // n = 7, score = 100
            //   8d2de07d5c00         | lea                 ebp, [0x5c7de0]
            //   892c24               | mov                 dword ptr [esp], ebp
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   897c2408             | mov                 dword ptr [esp + 8], edi
            //   894c240c             | mov                 dword ptr [esp + 0xc], ecx
            //   89742410             | mov                 dword ptr [esp + 0x10], esi
            //   e8????????           |                     

        $sequence_2 = { 8b6b24 896c2404 8d2d409a5c00 892c24 8d742440 89742408 e8???????? }
            // n = 7, score = 100
            //   8b6b24               | mov                 ebp, dword ptr [ebx + 0x24]
            //   896c2404             | mov                 dword ptr [esp + 4], ebp
            //   8d2d409a5c00         | lea                 ebp, [0x5c9a40]
            //   892c24               | mov                 dword ptr [esp], ebp
            //   8d742440             | lea                 esi, [esp + 0x40]
            //   89742408             | mov                 dword ptr [esp + 8], esi
            //   e8????????           |                     

        $sequence_3 = { f20f11440508 8d5301 89e8 89542418 8b5c2448 39da 0f8c5fffffff }
            // n = 7, score = 100
            //   f20f11440508         | movsd               qword ptr [ebp + eax + 8], xmm0
            //   8d5301               | lea                 edx, [ebx + 1]
            //   89e8                 | mov                 eax, ebp
            //   89542418             | mov                 dword ptr [esp + 0x18], edx
            //   8b5c2448             | mov                 ebx, dword ptr [esp + 0x48]
            //   39da                 | cmp                 edx, ebx
            //   0f8c5fffffff         | jl                  0xffffff65

        $sequence_4 = { ebdd 8d2de07d5c00 892c24 89442404 897c2408 894c240c 89742410 }
            // n = 7, score = 100
            //   ebdd                 | jmp                 0xffffffdf
            //   8d2de07d5c00         | lea                 ebp, [0x5c7de0]
            //   892c24               | mov                 dword ptr [esp], ebp
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   897c2408             | mov                 dword ptr [esp + 8], edi
            //   894c240c             | mov                 dword ptr [esp + 0xc], ecx
            //   89742410             | mov                 dword ptr [esp + 0x10], esi

        $sequence_5 = { c7042400000000 89442404 894c2408 8d053a026000 8944240c c744241002000000 e8???????? }
            // n = 7, score = 100
            //   c7042400000000       | mov                 dword ptr [esp], 0
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   894c2408             | mov                 dword ptr [esp + 8], ecx
            //   8d053a026000         | lea                 eax, [0x60023a]
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   c744241002000000     | mov                 dword ptr [esp + 0x10], 2
            //   e8????????           |                     

        $sequence_6 = { e9???????? 891424 894c2404 895c2408 e8???????? 8b54240c 8b4c2410 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   891424               | mov                 dword ptr [esp], edx
            //   894c2404             | mov                 dword ptr [esp + 4], ecx
            //   895c2408             | mov                 dword ptr [esp + 8], ebx
            //   e8????????           |                     
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]

        $sequence_7 = { 8d0598096000 890424 c744240405000000 8d055b396000 89442408 c744240c11000000 8d058a086000 }
            // n = 7, score = 100
            //   8d0598096000         | lea                 eax, [0x600998]
            //   890424               | mov                 dword ptr [esp], eax
            //   c744240405000000     | mov                 dword ptr [esp + 4], 5
            //   8d055b396000         | lea                 eax, [0x60395b]
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   c744240c11000000     | mov                 dword ptr [esp + 0xc], 0x11
            //   8d058a086000         | lea                 eax, [0x60088a]

        $sequence_8 = { 8d15e07b5c00 891424 c744240400000000 89442408 e8???????? 8b442410 8b4c240c }
            // n = 7, score = 100
            //   8d15e07b5c00         | lea                 edx, [0x5c7be0]
            //   891424               | mov                 dword ptr [esp], edx
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   e8????????           |                     
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]

        $sequence_9 = { 8d05354e6000 890424 c744240414000000 e8???????? 0f0b 8b15???????? 890a }
            // n = 7, score = 100
            //   8d05354e6000         | lea                 eax, [0x604e35]
            //   890424               | mov                 dword ptr [esp], eax
            //   c744240414000000     | mov                 dword ptr [esp + 4], 0x14
            //   e8????????           |                     
            //   0f0b                 | ud2                 
            //   8b15????????         |                     
            //   890a                 | mov                 dword ptr [edx], ecx

    condition:
        7 of them and filesize < 6545408
}