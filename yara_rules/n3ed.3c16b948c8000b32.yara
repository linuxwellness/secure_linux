import "hash"

rule n3ed_3c16b948c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.3c16b948c8000b32"
     cluster="n3ed.3c16b948c8000b32"
     cluster_size="568 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="attribute heuristic highconfidence"
     md5_hashes="['3d22e034c0c430f1c67514ca675e67ac', '82c326ba425893d9fa83c00ee1353bd3', '00ec1e8df127376355b0deffd067a2d2']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(240128,1024) == "847260ec25d49010b15515a5b48e567d"
}

