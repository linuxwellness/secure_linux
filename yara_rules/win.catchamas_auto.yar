rule win_catchamas_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.catchamas."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.catchamas"
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
        $sequence_0 = { 8b4018 3d00010000 7407 3d04010000 }
            // n = 4, score = 200
            //   8b4018               | mov                 eax, dword ptr [eax + 0x18]
            //   3d00010000           | cmp                 eax, 0x100
            //   7407                 | je                  9
            //   3d04010000           | cmp                 eax, 0x104

        $sequence_1 = { 5e 5b c20800 85c9 750a 6805400080 e8???????? }
            // n = 7, score = 200
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c20800               | ret                 8
            //   85c9                 | test                ecx, ecx
            //   750a                 | jne                 0xc
            //   6805400080           | push                0x80004005
            //   e8????????           |                     

        $sequence_2 = { 894604 33c0 39442418 0f9dc0 40 e8???????? 85db }
            // n = 7, score = 200
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   33c0                 | xor                 eax, eax
            //   39442418             | cmp                 dword ptr [esp + 0x18], eax
            //   0f9dc0               | setge               al
            //   40                   | inc                 eax
            //   e8????????           |                     
            //   85db                 | test                ebx, ebx

        $sequence_3 = { 57 8b4d10 8b542420 51 }
            // n = 4, score = 200
            //   57                   | push                edi
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   51                   | push                ecx

        $sequence_4 = { 5d c21000 6a10 8d442424 50 }
            // n = 5, score = 200
            //   5d                   | pop                 ebp
            //   c21000               | ret                 0x10
            //   6a10                 | push                0x10
            //   8d442424             | lea                 eax, [esp + 0x24]
            //   50                   | push                eax

        $sequence_5 = { 0fb7d8 6a14 81e300800000 ffd7 83e001 33c9 }
            // n = 6, score = 200
            //   0fb7d8               | movzx               ebx, ax
            //   6a14                 | push                0x14
            //   81e300800000         | and                 ebx, 0x8000
            //   ffd7                 | call                edi
            //   83e001               | and                 eax, 1
            //   33c9                 | xor                 ecx, ecx

        $sequence_6 = { e8???????? 8a4f01 0fb6c1 25ff000080 7907 48 0d00ffffff }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8a4f01               | mov                 cl, byte ptr [edi + 1]
            //   0fb6c1               | movzx               eax, cl
            //   25ff000080           | and                 eax, 0x800000ff
            //   7907                 | jns                 9
            //   48                   | dec                 eax
            //   0d00ffffff           | or                  eax, 0xffffff00

        $sequence_7 = { 50 e8???????? 85c0 0f8557010000 8b0d???????? 8b15???????? }
            // n = 6, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8557010000         | jne                 0x15d
            //   8b0d????????         |                     
            //   8b15????????         |                     

        $sequence_8 = { 0f85c9000000 85db 747d 53 ff15???????? 6a00 40 }
            // n = 7, score = 200
            //   0f85c9000000         | jne                 0xcf
            //   85db                 | test                ebx, ebx
            //   747d                 | je                  0x7f
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   40                   | inc                 eax

        $sequence_9 = { ff15???????? 83c42c eb24 8b4c2418 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   83c42c               | add                 esp, 0x2c
            //   eb24                 | jmp                 0x26
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]

    condition:
        7 of them and filesize < 368640
}