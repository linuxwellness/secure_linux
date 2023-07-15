/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-03
   Identifier: case120
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_06_03_18_case120_luk_ocl {
   meta:
      description = "case120 - file luk-ocl"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-03"
      hash1 = "8d5e3d2e57f975078033a9f6b3360c530512448dde517f484cdf86570c36d6ca"
   strings:
      $x1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s2 = "* hwloc %s has encountered what looks like an error from the operating system." fullword ascii
      $s3 = "Please verify that both the operating system and the processor support Intel(R) %s instructions." fullword ascii
      $s4 = "--host cryptonight.usa.nicehash.com --port 3355" fullword ascii
      $s5 = "Please verify that both the operating system and the processor support Intel(R) AVX, F16C and RDRAND instructions." fullword ascii
      $s6 = "-> share *accepted*: %ld/%ld (%.02f%%) - total hashrate %.02fH/s (may take a while to converge)" fullword ascii
      $s7 = "The attempt to get the address for the pool failed with code %d." fullword ascii
      $s8 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s9 = "--host xmr-usa.dwarfpool.com --port 8080" fullword ascii
      $s10 = "--host mine.aeon-pool.com --port 8080" fullword ascii
      $s11 = "--host pool.sumokoin.com --port 4444" fullword ascii
      $s12 = "* hwloc %s has encountered what looks like an error from user-given distances." fullword ascii
      $s13 = "Please verify that both the operating system and the processor support Intel(R) AVX." fullword ascii
      $s14 = "* Otherwise please report this error message to the hwloc user's mailing list," fullword ascii
      $s15 = "trtl.pool.mine2gether.com" fullword ascii
      $s16 = "Did not find any valid pu%%u entry in dumped cpuid directory `%s'" fullword ascii
      $s17 = "* to the hwloc's user mailing list together with the XML output of lstopo." fullword ascii
      $s18 = "* please report this error message to the hwloc user's mailing list," fullword ascii
      $s19 = "Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
      $s20 = "Found non-contigous pu%%u range in dumped cpuid directory `%s'" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 8000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_06_03_18_case120_luk_phi {
   meta:
      description = "case120 - file luk-phi"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-03"
      hash1 = "425f71ee456283d32673fcffe2641b5d6fbb1e91b2f15a91f9c34877a921ca75"
   strings:
      $x1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s2 = "Please verify that both the operating system and the processor support Intel(R) %s instructions." fullword ascii
      $s3 = "* hwloc %s has encountered what looks like an error from the operating system." fullword ascii
      $s4 = "--host cryptonight.usa.nicehash.com --port 3355" fullword ascii
      $s5 = "Please verify that both the operating system and the processor support Intel(R) AVX, F16C and RDRAND instructions." fullword ascii
      $s6 = "-> share *accepted*: %ld/%ld (%.02f%%) - total hashrate %.02fH/s (may take a while to converge)" fullword ascii
      $s7 = "The attempt to get the address for the pool failed with code %d." fullword ascii
      $s8 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s9 = "--host xmr-usa.dwarfpool.com --port 8080" fullword ascii
      $s10 = "# - all tuning parameters are auto-set and hardcoded             #" fullword ascii
      $s11 = "--host mine.aeon-pool.com --port 8080" fullword ascii
      $s12 = "--host pool.sumokoin.com --port 4444" fullword ascii
      $s13 = "* hwloc %s has encountered what looks like an error from user-given distances." fullword ascii
      $s14 = "Please verify that both the operating system and the processor support Intel(R) AVX." fullword ascii
      $s15 = "* Otherwise please report this error message to the hwloc user's mailing list," fullword ascii
      $s16 = "trtl.pool.mine2gether.com" fullword ascii
      $s17 = "Did not find any valid pu%%u entry in dumped cpuid directory `%s'" fullword ascii
      $s18 = "* to the hwloc's user mailing list together with the XML output of lstopo." fullword ascii
      $s19 = "* please report this error message to the hwloc user's mailing list," fullword ascii
      $s20 = "Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 8000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}


rule infected_06_03_18_case120_luk_cpu {
   meta:
      description = "case120 - file luk-cpu"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-03"
      hash1 = "76210f0a7710b40095d32f81bfb5d0576f81ac7cbdc63cf44ababb64cb8e65b7"
   strings:
      $x1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s2 = "Please verify that both the operating system and the processor support Intel(R) %s instructions." fullword ascii
      $s3 = "* hwloc %s has encountered what looks like an error from the operating system." fullword ascii
      $s4 = "--host cryptonight.usa.nicehash.com --port 3355" fullword ascii
      $s5 = "Please verify that both the operating system and the processor support Intel(R) AVX, F16C and RDRAND instructions." fullword ascii
      $s6 = "-> share *accepted*: %ld/%ld (%.02f%%) - total hashrate %.02fH/s (may take a while to converge)" fullword ascii
      $s7 = "The attempt to get the address for the pool failed with code %d." fullword ascii
      $s8 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s9 = "--host xmr-usa.dwarfpool.com --port 8080" fullword ascii
      $s10 = "--host mine.aeon-pool.com --port 8080" fullword ascii
      $s11 = "--host pool.sumokoin.com --port 4444" fullword ascii
      $s12 = "* hwloc %s has encountered what looks like an error from user-given distances." fullword ascii
      $s13 = "Please verify that both the operating system and the processor support Intel(R) AVX." fullword ascii
      $s14 = "* Otherwise please report this error message to the hwloc user's mailing list," fullword ascii
      $s15 = "trtl.pool.mine2gether.com" fullword ascii
      $s16 = "Did not find any valid pu%%u entry in dumped cpuid directory `%s'" fullword ascii
      $s17 = "* to the hwloc's user mailing list together with the XML output of lstopo." fullword ascii
      $s18 = "* please report this error message to the hwloc user's mailing list," fullword ascii
      $s19 = "Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
      $s20 = "Found non-contigous pu%%u range in dumped cpuid directory `%s'" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 8000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _luk_cpu_luk_ocl_luk_phi_0 {
   meta:
      description = "case120 - from files luk-cpu, luk-ocl, luk-phi"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-03"
      hash1 = "76210f0a7710b40095d32f81bfb5d0576f81ac7cbdc63cf44ababb64cb8e65b7"
      hash2 = "8d5e3d2e57f975078033a9f6b3360c530512448dde517f484cdf86570c36d6ca"
      hash3 = "425f71ee456283d32673fcffe2641b5d6fbb1e91b2f15a91f9c34877a921ca75"
   strings:
      $x1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s2 = "Please verify that both the operating system and the processor support Intel(R) %s instructions." fullword ascii
      $s3 = "* hwloc %s has encountered what looks like an error from the operating system." fullword ascii
      $s4 = "--host cryptonight.usa.nicehash.com --port 3355" fullword ascii
      $s5 = "Please verify that both the operating system and the processor support Intel(R) AVX, F16C and RDRAND instructions." fullword ascii
      $s6 = "-> share *accepted*: %ld/%ld (%.02f%%) - total hashrate %.02fH/s (may take a while to converge)" fullword ascii
      $s7 = "The attempt to get the address for the pool failed with code %d." fullword ascii
      $s8 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s9 = "--host xmr-usa.dwarfpool.com --port 8080" fullword ascii
      $s10 = "--host mine.aeon-pool.com --port 8080" fullword ascii
      $s11 = "--host pool.sumokoin.com --port 4444" fullword ascii
      $s12 = "* hwloc %s has encountered what looks like an error from user-given distances." fullword ascii
      $s13 = "* Otherwise please report this error message to the hwloc user's mailing list," fullword ascii
      $s14 = "Please verify that both the operating system and the processor support Intel(R) AVX." fullword ascii
      $s15 = "trtl.pool.mine2gether.com" fullword ascii
      $s16 = "Did not find any valid pu%%u entry in dumped cpuid directory `%s'" fullword ascii
      $s17 = "* to the hwloc's user mailing list together with the XML output of lstopo." fullword ascii
      $s18 = "* please report this error message to the hwloc user's mailing list," fullword ascii
      $s19 = "Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
      $s20 = "Found non-contigous pu%%u range in dumped cpuid directory `%s'" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
        filesize < 8000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

