rule win_opachki_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.opachki."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.opachki"
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
        $sequence_0 = { 85c0 7437 8b4e08 03c8 51 }
            // n = 5, score = 300
            //   85c0                 | test                eax, eax
            //   7437                 | je                  0x39
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   03c8                 | add                 ecx, eax
            //   51                   | push                ecx

        $sequence_1 = { c3 55 8bec 81ec00010000 ff7508 }
            // n = 5, score = 300
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec00010000         | sub                 esp, 0x100
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_2 = { 8d8500ffffff 50 ff15???????? 50 68???????? 8d8500ffffff }
            // n = 6, score = 300
            //   8d8500ffffff         | lea                 eax, [ebp - 0x100]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   50                   | push                eax
            //   68????????           |                     
            //   8d8500ffffff         | lea                 eax, [ebp - 0x100]

        $sequence_3 = { 56 6a02 6800000040 ff750c ff15???????? }
            // n = 5, score = 300
            //   56                   | push                esi
            //   6a02                 | push                2
            //   6800000040           | push                0x40000000
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff15????????         |                     

        $sequence_4 = { ff4d08 75c4 83c8ff 5f }
            // n = 4, score = 300
            //   ff4d08               | dec                 dword ptr [ebp + 8]
            //   75c4                 | jne                 0xffffffc6
            //   83c8ff               | or                  eax, 0xffffffff
            //   5f                   | pop                 edi

        $sequence_5 = { 53 6a01 6800000080 8d85e0feffff 50 }
            // n = 5, score = 300
            //   53                   | push                ebx
            //   6a01                 | push                1
            //   6800000080           | push                0x80000000
            //   8d85e0feffff         | lea                 eax, [ebp - 0x120]
            //   50                   | push                eax

        $sequence_6 = { 8bc3 897d0c 7422 8bd7 2bd7 }
            // n = 5, score = 300
            //   8bc3                 | mov                 eax, ebx
            //   897d0c               | mov                 dword ptr [ebp + 0xc], edi
            //   7422                 | je                  0x24
            //   8bd7                 | mov                 edx, edi
            //   2bd7                 | sub                 edx, edi

        $sequence_7 = { 89460c ff15???????? 59 894604 }
            // n = 4, score = 300
            //   89460c               | mov                 dword ptr [esi + 0xc], eax
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   894604               | mov                 dword ptr [esi + 4], eax

        $sequence_8 = { 88770b c0e002 c0e805 88470a 3c01 ac }
            // n = 6, score = 200
            //   88770b               | mov                 byte ptr [edi + 0xb], dh
            //   c0e002               | shl                 al, 2
            //   c0e805               | shr                 al, 5
            //   88470a               | mov                 byte ptr [edi + 0xa], al
            //   3c01                 | cmp                 al, 1
            //   ac                   | lodsb               al, byte ptr [esi]

        $sequence_9 = { 884717 80ff02 7506 66ad }
            // n = 4, score = 200
            //   884717               | mov                 byte ptr [edi + 0x17], al
            //   80ff02               | cmp                 bh, 2
            //   7506                 | jne                 8
            //   66ad                 | lodsw               ax, word ptr [esi]

        $sequence_10 = { 3c66 7507 884704 b201 ebc1 }
            // n = 5, score = 200
            //   3c66                 | cmp                 al, 0x66
            //   7507                 | jne                 9
            //   884704               | mov                 byte ptr [edi + 4], al
            //   b201                 | mov                 dl, 1
            //   ebc1                 | jmp                 0xffffffc3

        $sequence_11 = { 89471a f6c110 7427 f6c140 }
            // n = 4, score = 200
            //   89471a               | mov                 dword ptr [edi + 0x1a], eax
            //   f6c110               | test                cl, 0x10
            //   7427                 | je                  0x29
            //   f6c140               | test                cl, 0x40

        $sequence_12 = { 884702 ebe9 3c2e 7414 3c36 }
            // n = 5, score = 200
            //   884702               | mov                 byte ptr [edi + 2], al
            //   ebe9                 | jmp                 0xffffffeb
            //   3c2e                 | cmp                 al, 0x2e
            //   7414                 | je                  0x16
            //   3c36                 | cmp                 al, 0x36

        $sequence_13 = { 80fd01 7502 b701 80fd02 750a 08db }
            // n = 6, score = 200
            //   80fd01               | cmp                 ch, 1
            //   7502                 | jne                 4
            //   b701                 | mov                 bh, 1
            //   80fd02               | cmp                 ch, 2
            //   750a                 | jne                 0xc
            //   08db                 | or                  bl, bl

        $sequence_14 = { 80ff04 7504 ad 89471a }
            // n = 4, score = 200
            //   80ff04               | cmp                 bh, 4
            //   7504                 | jne                 6
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   89471a               | mov                 dword ptr [edi + 0x1a], eax

    condition:
        7 of them and filesize < 122880
}