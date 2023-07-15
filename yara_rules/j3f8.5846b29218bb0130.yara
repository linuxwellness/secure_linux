
rule j3f8_5846b29218bb0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5846b29218bb0130"
     cluster="j3f8.5846b29218bb0130"
     cluster_size="187"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos apprisk"
     md5_hashes="['add8229fc6e00b4559f370b9d6d16063342be87a','3bf486f3cada28bd33d4b2d278ead16a65ae5ab5','14c5b534e2363528a90c0afa9ca0a7ad4b4f5169']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5846b29218bb0130"

   strings:
      $hex_string = { 2f706d2f4170706c69636174696f6e496e666f3b00234c616e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b00224c616e6472 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
