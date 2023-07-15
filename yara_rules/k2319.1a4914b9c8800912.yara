
rule k2319_1a4914b9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a4914b9c8800912"
     cluster="k2319.1a4914b9c8800912"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['177f352e250a9565a7aa32080bc047022258fd3b','d6fc3059d46fc5e90abd9c529d9106d72f463bcb','2e338879a302075648f5ded7eb9e28186c7e53f6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a4914b9c8800912"

   strings:
      $hex_string = { 646f773b666f7228766172206a335620696e207a30693356297b6966286a33562e6c656e6774683d3d3d2828307843462c3538293e31322e3f2838392e354531 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
