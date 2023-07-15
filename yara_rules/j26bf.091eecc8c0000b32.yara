
rule j26bf_091eecc8c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.091eecc8c0000b32"
     cluster="j26bf.091eecc8c0000b32"
     cluster_size="721"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="starter malicious atros"
     md5_hashes="['a6597d5bbfee25e54646c8a3b3c57eac2a913eb0','b983539ec630f4603d4d03dad3861fcfffcab756','5e7d8d2fd324d953673ed3f7c96f83449ea168b8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.091eecc8c0000b32"

   strings:
      $hex_string = { 734f626a65637450726f7669646572004170706c69636174696f6e00576562536572766963657300457175616c73006f0047657448617368436f646500547970 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
