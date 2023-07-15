
rule j2319_62859ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.62859ec1c8000b12"
     cluster="j2319.62859ec1c8000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script browsermodifier"
     md5_hashes="['55fc7cd7474933091cffea5b8a69151ba4451352','d96112075b370b7b769fe70ed84084fab0d2928b','0922cce40face09f698b085b3b12e0977020d306']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.62859ec1c8000b12"

   strings:
      $hex_string = { 4a7a7928612e73636f6465293b7472797b76617220633d612e65706f63682d6d6e672e65706f636828293b333630303e63262673657454696d656f7574287379 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
