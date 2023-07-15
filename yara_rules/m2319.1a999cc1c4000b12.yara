
rule m2319_1a999cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1a999cc1c4000b12"
     cluster="m2319.1a999cc1c4000b12"
     cluster_size="63"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['a899e91a4dd57396588305fb4b033a43f53d27bb','9d585439a23a77db17072a9dfb6b0f06de564d34','4cc9041d7d1fa7e89bd22ec538e35e2403c604a5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1a999cc1c4000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
