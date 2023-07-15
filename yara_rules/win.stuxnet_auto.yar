rule win_stuxnet_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.stuxnet."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stuxnet"
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
        $sequence_0 = { b8???????? e8???????? 51 51 56 894df0 c701???????? }
            // n = 7, score = 200
            //   b8????????           |                     
            //   e8????????           |                     
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   56                   | push                esi
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   c701????????         |                     

        $sequence_1 = { c645fc05 c645fc06 e8???????? 8b7810 c645fc04 8d45e4 50 }
            // n = 7, score = 200
            //   c645fc05             | mov                 byte ptr [ebp - 4], 5
            //   c645fc06             | mov                 byte ptr [ebp - 4], 6
            //   e8????????           |                     
            //   8b7810               | mov                 edi, dword ptr [eax + 0x10]
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax

        $sequence_2 = { c645fc01 85f6 7414 53 e8???????? c645fc02 8a431c }
            // n = 7, score = 200
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   85f6                 | test                esi, esi
            //   7414                 | je                  0x16
            //   53                   | push                ebx
            //   e8????????           |                     
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   8a431c               | mov                 al, byte ptr [ebx + 0x1c]

        $sequence_3 = { ff742414 e8???????? 5f 59 c20400 b8???????? e8???????? }
            // n = 7, score = 200
            //   ff742414             | push                dword ptr [esp + 0x14]
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   59                   | pop                 ecx
            //   c20400               | ret                 4
            //   b8????????           |                     
            //   e8????????           |                     

        $sequence_4 = { 33c0 75fc 8b450c 8b8d70ffffff 898880000000 83a578ffffff00 8b4588 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   75fc                 | jne                 0xfffffffe
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b8d70ffffff         | mov                 ecx, dword ptr [ebp - 0x90]
            //   898880000000         | mov                 dword ptr [eax + 0x80], ecx
            //   83a578ffffff00       | and                 dword ptr [ebp - 0x88], 0
            //   8b4588               | mov                 eax, dword ptr [ebp - 0x78]

        $sequence_5 = { be00100000 56 33db 53 ff15???????? 8bf8 85ff }
            // n = 7, score = 200
            //   be00100000           | mov                 esi, 0x1000
            //   56                   | push                esi
            //   33db                 | xor                 ebx, ebx
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi

        $sequence_6 = { e8???????? 837da8ff 7599 8b4508 8b403c 33c9 85c0 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   837da8ff             | cmp                 dword ptr [ebp - 0x58], -1
            //   7599                 | jne                 0xffffff9b
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b403c               | mov                 eax, dword ptr [eax + 0x3c]
            //   33c9                 | xor                 ecx, ecx
            //   85c0                 | test                eax, eax

        $sequence_7 = { e8???????? 83c40c 837df400 8d45f0 50 7456 57 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   7456                 | je                  0x58
            //   57                   | push                edi

        $sequence_8 = { eb02 33c0 c9 c3 55 8bec 837d1c00 }
            // n = 7, score = 200
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   837d1c00             | cmp                 dword ptr [ebp + 0x1c], 0

        $sequence_9 = { c20400 6a00 56 50 ff15???????? 3d02010000 74e8 }
            // n = 7, score = 200
            //   c20400               | ret                 4
            //   6a00                 | push                0
            //   56                   | push                esi
            //   50                   | push                eax
            //   ff15????????         |                     
            //   3d02010000           | cmp                 eax, 0x102
            //   74e8                 | je                  0xffffffea

    condition:
        7 of them and filesize < 2495488
}