
rule m2319_14b21cc1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.14b21cc1c8000932"
     cluster="m2319.14b21cc1c8000932"
     cluster_size="93"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['487d9ff3ad9647b606b163c789562349bdb616b2','d3ead9ee08f3b32f5b80208287899a7b2e9916f5','ea7b063f9ed8d49f8317966e30eb4782181690c9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.14b21cc1c8000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
