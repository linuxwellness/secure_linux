rule win_upas_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.upas."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.upas"
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
        $sequence_0 = { 8a06 3ccf 75df 8bc7 5f 5e c3 }
            // n = 7, score = 400
            //   8a06                 | mov                 al, byte ptr [esi]
            //   3ccf                 | cmp                 al, 0xcf
            //   75df                 | jne                 0xffffffe1
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 

        $sequence_1 = { 8d45fc 50 57 57 8d855cfcffff 50 ff15???????? }
            // n = 7, score = 400
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   57                   | push                edi
            //   57                   | push                edi
            //   8d855cfcffff         | lea                 eax, [ebp - 0x3a4]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_2 = { 33ff 897de8 897df4 ff15???????? }
            // n = 4, score = 400
            //   33ff                 | xor                 edi, edi
            //   897de8               | mov                 dword ptr [ebp - 0x18], edi
            //   897df4               | mov                 dword ptr [ebp - 0xc], edi
            //   ff15????????         |                     

        $sequence_3 = { c78500fdffff3f000100 ff15???????? 85c0 7878 6a40 }
            // n = 5, score = 400
            //   c78500fdffff3f000100     | mov    dword ptr [ebp - 0x300], 0x1003f
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7878                 | js                  0x7a
            //   6a40                 | push                0x40

        $sequence_4 = { 50 ff7508 8d8574f4ffff 68???????? }
            // n = 4, score = 400
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8d8574f4ffff         | lea                 eax, [ebp - 0xb8c]
            //   68????????           |                     

        $sequence_5 = { 8d45f8 50 e8???????? 8d85ecfdffff 68???????? 50 }
            // n = 6, score = 400
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d85ecfdffff         | lea                 eax, [ebp - 0x214]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_6 = { 50 6a15 8d45cc 50 }
            // n = 4, score = 400
            //   50                   | push                eax
            //   6a15                 | push                0x15
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   50                   | push                eax

        $sequence_7 = { eb39 83fe01 7504 0bcd eb19 }
            // n = 5, score = 400
            //   eb39                 | jmp                 0x3b
            //   83fe01               | cmp                 esi, 1
            //   7504                 | jne                 6
            //   0bcd                 | or                  ecx, ebp
            //   eb19                 | jmp                 0x1b

        $sequence_8 = { e8???????? 59 59 85c0 0f846affffff 837d7001 7523 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   0f846affffff         | je                  0xffffff70
            //   837d7001             | cmp                 dword ptr [ebp + 0x70], 1
            //   7523                 | jne                 0x25

        $sequence_9 = { 6a03 ff7508 895dfc ff15???????? }
            // n = 4, score = 400
            //   6a03                 | push                3
            //   ff7508               | push                dword ptr [ebp + 8]
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 114688
}