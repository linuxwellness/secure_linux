
rule j26bf_07a46b44c0000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.07a46b44c0000112"
     cluster="j26bf.07a46b44c0000112"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy tsklnk dotdo"
     md5_hashes="['90599e5275743670f0d57064baacf1157f2cb0bd','0add13c3c2947b6a0ce6af88f22a8ea5f3d1089a','f3f4d2372861de6d6d5c8f352ceea8fd50f57755']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.07a46b44c0000112"

   strings:
      $hex_string = { 747269627574650053797374656d2e52756e74696d652e496e7465726f70536572766963657300436f6d56697369626c65417474726962757465004775696441 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
