
rule k2318_391a53c9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.391a53c9c8000b32"
     cluster="k2318.391a53c9c8000b32"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['9ce6630da0f0593aaa78ad7b6556f15bc2aaddaf','03479be56dddee2191b220053863bac610ea7b50','5b98e81a49d439714aa3b65b24cc4bca32246585']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.391a53c9c8000b32"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
