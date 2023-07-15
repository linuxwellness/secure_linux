rule win_nabucur_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.nabucur."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nabucur"
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
        $sequence_0 = { 48 894500 85c0 7fee }
            // n = 4, score = 200
            //   48                   | dec                 eax
            //   894500               | mov                 dword ptr [ebp], eax
            //   85c0                 | test                eax, eax
            //   7fee                 | jg                  0xfffffff0

        $sequence_1 = { 49 23cf 894c241c 3bc3 }
            // n = 4, score = 200
            //   49                   | dec                 ecx
            //   23cf                 | and                 ecx, edi
            //   894c241c             | mov                 dword ptr [esp + 0x1c], ecx
            //   3bc3                 | cmp                 eax, ebx

        $sequence_2 = { 49 03d3 40 85c9 }
            // n = 4, score = 200
            //   49                   | dec                 ecx
            //   03d3                 | add                 edx, ebx
            //   40                   | inc                 eax
            //   85c9                 | test                ecx, ecx

        $sequence_3 = { 33ff 397c242c 7e61 8b6c242c 8b03 }
            // n = 5, score = 200
            //   33ff                 | xor                 edi, edi
            //   397c242c             | cmp                 dword ptr [esp + 0x2c], edi
            //   7e61                 | jle                 0x63
            //   8b6c242c             | mov                 ebp, dword ptr [esp + 0x2c]
            //   8b03                 | mov                 eax, dword ptr [ebx]

        $sequence_4 = { 48 8944241c 85c0 7fd1 5f }
            // n = 5, score = 200
            //   48                   | dec                 eax
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   85c0                 | test                eax, eax
            //   7fd1                 | jg                  0xffffffd3
            //   5f                   | pop                 edi

        $sequence_5 = { 49 23cb 894d08 5d }
            // n = 4, score = 200
            //   49                   | dec                 ecx
            //   23cb                 | and                 ecx, ebx
            //   894d08               | mov                 dword ptr [ebp + 8], ecx
            //   5d                   | pop                 ebp

        $sequence_6 = { 49 23ce 894f18 8bf0 85c0 0f8521040000 }
            // n = 6, score = 200
            //   49                   | dec                 ecx
            //   23ce                 | and                 ecx, esi
            //   894f18               | mov                 dword ptr [edi + 0x18], ecx
            //   8bf0                 | mov                 esi, eax
            //   85c0                 | test                eax, eax
            //   0f8521040000         | jne                 0x427

        $sequence_7 = { 009eaa030000 0fb686aa030000 57 83f80a 0f876d010000 }
            // n = 5, score = 200
            //   009eaa030000         | add                 byte ptr [esi + 0x3aa], bl
            //   0fb686aa030000       | movzx               eax, byte ptr [esi + 0x3aa]
            //   57                   | push                edi
            //   83f80a               | cmp                 eax, 0xa
            //   0f876d010000         | ja                  0x173

        $sequence_8 = { 89fc 2330 89ed 326284 e728 }
            // n = 5, score = 100
            //   89fc                 | mov                 esp, edi
            //   2330                 | and                 esi, dword ptr [eax]
            //   89ed                 | mov                 ebp, ebp
            //   326284               | xor                 ah, byte ptr [edx - 0x7c]
            //   e728                 | out                 0x28, eax

        $sequence_9 = { 8bec 83ec0c 6a00 6a01 8d05f7d04000 50 }
            // n = 6, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83ec0c               | sub                 esp, 0xc
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   8d05f7d04000         | lea                 eax, [0x40d0f7]
            //   50                   | push                eax

        $sequence_10 = { 7913 6c 148c 66ffd3 fb }
            // n = 5, score = 100
            //   7913                 | jns                 0x15
            //   6c                   | insb                byte ptr es:[edi], dx
            //   148c                 | adc                 al, 0x8c
            //   66ffd3               | call                bx
            //   fb                   | sti                 

        $sequence_11 = { 8bec b801000000 8705???????? 83f800 }
            // n = 4, score = 100
            //   8bec                 | mov                 ebp, esp
            //   b801000000           | mov                 eax, 1
            //   8705????????         |                     
            //   83f800               | cmp                 eax, 0

        $sequence_12 = { 764a b303 fc 4f 227fb1 4f }
            // n = 6, score = 100
            //   764a                 | jbe                 0x4c
            //   b303                 | mov                 bl, 3
            //   fc                   | cld                 
            //   4f                   | dec                 edi
            //   227fb1               | and                 bh, byte ptr [edi - 0x4f]
            //   4f                   | dec                 edi

        $sequence_13 = { ae 8627 d593 51 5b }
            // n = 5, score = 100
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   8627                 | xchg                byte ptr [edi], ah
            //   d593                 | aad                 0x93
            //   51                   | push                ecx
            //   5b                   | pop                 ebx

        $sequence_14 = { 004900 6800720020 005300 7900 }
            // n = 4, score = 100
            //   004900               | add                 byte ptr [ecx], cl
            //   6800720020           | push                0x20007200
            //   005300               | add                 byte ptr [ebx], dl
            //   7900                 | jns                 2

        $sequence_15 = { bb921d94fd 3006 eb6e 83c604 bb2d7d36f9 83e904 }
            // n = 6, score = 100
            //   bb921d94fd           | mov                 ebx, 0xfd941d92
            //   3006                 | xor                 byte ptr [esi], al
            //   eb6e                 | jmp                 0x70
            //   83c604               | add                 esi, 4
            //   bb2d7d36f9           | mov                 ebx, 0xf9367d2d
            //   83e904               | sub                 ecx, 4

    condition:
        7 of them and filesize < 1949696
}