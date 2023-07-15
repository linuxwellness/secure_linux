
rule m2319_16b29cc1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.16b29cc1c4000932"
     cluster="m2319.16b29cc1c4000932"
     cluster_size="167"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['19fd5f91fbcfcdfbf13a1994138c789b1e112633','c27b2dd9d815bfcbe01f5b39ef34bd50d207b0bb','5b5c62fb08c5779ae2be3d7cfb813939cf7edd59']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.16b29cc1c4000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
