rule win_zxxz_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.zxxz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zxxz"
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
        $sequence_0 = { 68???????? ffd6 83c40c 33c0 }
            // n = 4, score = 100
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   83c40c               | add                 esp, 0xc
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 740b 8a81315c4000 41 84c0 75f1 8a81315c4000 }
            // n = 6, score = 100
            //   740b                 | je                  0xd
            //   8a81315c4000         | mov                 al, byte ptr [ecx + 0x405c31]
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al
            //   75f1                 | jne                 0xfffffff3
            //   8a81315c4000         | mov                 al, byte ptr [ecx + 0x405c31]

        $sequence_2 = { 40 84c9 75f9 2bc2 8b54240c 50 68???????? }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75f9                 | jne                 0xfffffffb
            //   2bc2                 | sub                 eax, edx
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_3 = { 51 68???????? e8???????? 8d842414020000 83c40c 8d5001 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   68????????           |                     
            //   e8????????           |                     
            //   8d842414020000       | lea                 eax, [esp + 0x214]
            //   83c40c               | add                 esp, 0xc
            //   8d5001               | lea                 edx, [eax + 1]

        $sequence_4 = { 33c0 e9???????? 68???????? 8d4c2414 68fa000000 51 }
            // n = 6, score = 100
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   68????????           |                     
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   68fa000000           | push                0xfa
            //   51                   | push                ecx

        $sequence_5 = { a1???????? 33c4 89442434 55 56 57 }
            // n = 6, score = 100
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   89442434             | mov                 dword ptr [esp + 0x34], eax
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_6 = { 68???????? c705????????524e4700 ffd6 83c40c 68???????? }
            // n = 5, score = 100
            //   68????????           |                     
            //   c705????????524e4700     |     
            //   ffd6                 | call                esi
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     

        $sequence_7 = { 6a00 6a00 6a15 6a00 ffd6 85c0 743d }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a15                 | push                0x15
            //   6a00                 | push                0
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   743d                 | je                  0x3f

        $sequence_8 = { 51 68???????? e8???????? 8d842414020000 }
            // n = 4, score = 100
            //   51                   | push                ecx
            //   68????????           |                     
            //   e8????????           |                     
            //   8d842414020000       | lea                 eax, [esp + 0x214]

        $sequence_9 = { 50 6a00 6a00 6a15 6a00 ffd6 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a15                 | push                0x15
            //   6a00                 | push                0
            //   ffd6                 | call                esi

    condition:
        7 of them and filesize < 4142080
}