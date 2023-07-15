
rule m2319_150ab7a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.150ab7a1c2000932"
     cluster="m2319.150ab7a1c2000932"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['3d4797f92fb54e7944a9d52797c62d7159ffc1ff','f245c267550e8d9dc2dc0e7cea293c2f959c31cf','5f2e994875349e5453062491688a607ff5912f3f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.150ab7a1c2000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
