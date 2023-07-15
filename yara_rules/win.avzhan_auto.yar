rule win_avzhan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.avzhan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.avzhan"
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
        $sequence_0 = { 8b2d???????? 8b1d???????? b910000000 33c0 8d7c243c c744243844000000 }
            // n = 6, score = 200
            //   8b2d????????         |                     
            //   8b1d????????         |                     
            //   b910000000           | mov                 ecx, 0x10
            //   33c0                 | xor                 eax, eax
            //   8d7c243c             | lea                 edi, [esp + 0x3c]
            //   c744243844000000     | mov                 dword ptr [esp + 0x38], 0x44

        $sequence_1 = { 8b3d???????? 83c418 0bc6 8944244c 66c74424500000 3935???????? }
            // n = 6, score = 200
            //   8b3d????????         |                     
            //   83c418               | add                 esp, 0x18
            //   0bc6                 | or                  eax, esi
            //   8944244c             | mov                 dword ptr [esp + 0x4c], eax
            //   66c74424500000       | mov                 word ptr [esp + 0x50], 0
            //   3935????????         |                     

        $sequence_2 = { 52 ffd3 6a0a ffd7 ebbc 6a00 ff15???????? }
            // n = 7, score = 200
            //   52                   | push                edx
            //   ffd3                 | call                ebx
            //   6a0a                 | push                0xa
            //   ffd7                 | call                edi
            //   ebbc                 | jmp                 0xffffffbe
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_3 = { 83c418 0bc6 8944244c 66c74424500000 }
            // n = 4, score = 200
            //   83c418               | add                 esp, 0x18
            //   0bc6                 | or                  eax, esi
            //   8944244c             | mov                 dword ptr [esp + 0x4c], eax
            //   66c74424500000       | mov                 word ptr [esp + 0x50], 0

        $sequence_4 = { 6a00 6a00 6a00 8d8c2418020000 6a00 51 6a00 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d8c2418020000       | lea                 ecx, [esp + 0x218]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   6a00                 | push                0

        $sequence_5 = { 8b1d???????? 83c418 3935???????? 7450 }
            // n = 4, score = 200
            //   8b1d????????         |                     
            //   83c418               | add                 esp, 0x18
            //   3935????????         |                     
            //   7450                 | je                  0x52

        $sequence_6 = { e8???????? 83c061 8bcb 8ad8 8bd1 8afb }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83c061               | add                 eax, 0x61
            //   8bcb                 | mov                 ecx, ebx
            //   8ad8                 | mov                 bl, al
            //   8bd1                 | mov                 edx, ecx
            //   8afb                 | mov                 bh, bl

        $sequence_7 = { 8d8c240c020000 68???????? 51 ff15???????? 8b2d???????? 8b1d???????? }
            // n = 6, score = 200
            //   8d8c240c020000       | lea                 ecx, [esp + 0x20c]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b2d????????         |                     
            //   8b1d????????         |                     

        $sequence_8 = { 7410 68d0070000 ffd7 6a00 }
            // n = 4, score = 200
            //   7410                 | je                  0x12
            //   68d0070000           | push                0x7d0
            //   ffd7                 | call                edi
            //   6a00                 | push                0

        $sequence_9 = { 3935???????? 7450 8b942464010000 8d442464 52 50 e8???????? }
            // n = 7, score = 200
            //   3935????????         |                     
            //   7450                 | je                  0x52
            //   8b942464010000       | mov                 edx, dword ptr [esp + 0x164]
            //   8d442464             | lea                 eax, [esp + 0x64]
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 122880
}