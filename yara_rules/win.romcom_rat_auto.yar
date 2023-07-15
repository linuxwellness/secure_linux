rule win_romcom_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.romcom_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.romcom_rat"
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
        $sequence_0 = { 488bc8 41ffd0 488975d7 488975e7 48c745ef0f000000 408875d7 488b03 }
            // n = 7, score = 100
            //   488bc8               | dec                 eax
            //   41ffd0               | lea                 edx, [ebp - 0x49]
            //   488975d7             | dec                 eax
            //   488975e7             | mov                 ecx, dword ptr [ebp - 0x49]
            //   48c745ef0f000000     | dec                 esp
            //   408875d7             | mov                 eax, dword ptr [ebp - 0x31]
            //   488b03               | jle                 0x2c0

        $sequence_1 = { 66443921 75f6 8b05???????? 8901 448925???????? 458bfc 4489a5e0110000 }
            // n = 7, score = 100
            //   66443921             | dec                 esp
            //   75f6                 | mov                 esp, dword ptr [esp + 0x50]
            //   8b05????????         |                     
            //   8901                 | inc                 ecx
            //   448925????????       |                     
            //   458bfc               | bts                 esp, 8
            //   4489a5e0110000       | inc                 ecx

        $sequence_2 = { 448bc6 ba01000000 ffd0 48894740 4885c0 7517 488b5738 }
            // n = 7, score = 100
            //   448bc6               | inc                 ebp
            //   ba01000000           | xor                 ecx, ecx
            //   ffd0                 | inc                 ecx
            //   48894740             | mov                 eax, 0x1000
            //   4885c0               | dec                 ecx
            //   7517                 | mov                 ecx, edi
            //   488b5738             | dec                 ecx

        $sequence_3 = { 488d0582180600 488901 8bf2 488bd9 4885ff 743c 488b4f08 }
            // n = 7, score = 100
            //   488d0582180600       | mov                 esi, 0x1000
            //   488901               | mov                 byte ptr [ecx + edx], al
            //   8bf2                 | dec                 eax
            //   488bd9               | inc                 edx
            //   4885ff               | test                al, al
            //   743c                 | jne                 0x965
            //   488b4f08             | dec                 eax

        $sequence_4 = { 488bec 4883ec70 4d8bf1 4d8bf8 488bf2 488bf9 4885c9 }
            // n = 7, score = 100
            //   488bec               | inc                 ecx
            //   4883ec70             | mov                 edx, dword ptr [esi + 0x94]
            //   4d8bf1               | mov                 ebx, 0x4000
            //   4d8bf8               | dec                 ecx
            //   488bf2               | mov                 ecx, dword ptr [esi + 0x88]
            //   488bf9               | cmp                 eax, ebx
            //   4885c9               | test                eax, eax

        $sequence_5 = { 740a 488d4c2420 e8???????? b804000000 488b9c24b8000000 4881c490000000 5f }
            // n = 7, score = 100
            //   740a                 | inc                 ebp
            //   488d4c2420           | movzx               ecx, si
            //   e8????????           |                     
            //   b804000000           | dec                 esp
            //   488b9c24b8000000     | lea                 eax, [ebp - 0x61]
            //   4881c490000000       | dec                 eax
            //   5f                   | lea                 edx, [ebp - 0x51]

        $sequence_6 = { 807b0100 7ec2 48ffc3 ebbd c644243201 eb07 c644243201 }
            // n = 7, score = 100
            //   807b0100             | mov                 eax, dword ptr [ecx]
            //   7ec2                 | dec                 eax
            //   48ffc3               | mov                 eax, dword ptr [eax + 0x38]
            //   ebbd                 | inc                 ebp
            //   c644243201           | xor                 eax, eax
            //   eb07                 | cmp                 si, ax
            //   c644243201           | movzx               eax, word ptr [edx]

        $sequence_7 = { 488364243000 c744242828000000 8364242000 0f11442458 ff15???????? 85c0 7416 }
            // n = 7, score = 100
            //   488364243000         | dec                 eax
            //   c744242828000000     | mov                 eax, dword ptr [esi]
            //   8364242000           | dec                 eax
            //   0f11442458           | lea                 edx, [ebp - 0x7c]
            //   ff15????????         |                     
            //   85c0                 | dec                 esp
            //   7416                 | mov                 dword ptr [esi + 0x10], esp

        $sequence_8 = { 4833c4 48894518 4c894c2440 4d8be8 488bfa 4889542458 488955b0 }
            // n = 7, score = 100
            //   4833c4               | mov                 ecx, 0x80
            //   48894518             | movups              xmm0, xmmword ptr [edi]
            //   4c894c2440           | movups              xmmword ptr [eax], xmm0
            //   4d8be8               | movups              xmm1, xmmword ptr [edi + 0x10]
            //   488bfa               | movups              xmmword ptr [eax + 0x10], xmm1
            //   4889542458           | dec                 ecx
            //   488955b0             | lea                 eax, [esi + 0x10]

        $sequence_9 = { 4c896c2428 488d4588 4889442420 4533c9 4533c0 33d2 488b4c2470 }
            // n = 7, score = 100
            //   4c896c2428           | lea                 ecx, [ecx + 2]
            //   488d4588             | inc                 sp
            //   4889442420           | cmp                 dword ptr [ecx], esp
            //   4533c9               | dec                 esp
            //   4533c0               | mov                 eax, eax
            //   33d2                 | dec                 eax
            //   488b4c2470           | lea                 ecx, [ebp + 0x1060]

    condition:
        7 of them and filesize < 1211392
}