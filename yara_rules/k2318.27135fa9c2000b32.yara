
rule k2318_27135fa9c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27135fa9c2000b32"
     cluster="k2318.27135fa9c2000b32"
     cluster_size="66"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['6585c58cc7191fdd48619da965fc6727d1ac916e','6ee1cef11e85b15c56ada9edde31e59515626ad7','6b9ca6a6f76d33f11f6a99d8557f261532cd78a8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27135fa9c2000b32"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
