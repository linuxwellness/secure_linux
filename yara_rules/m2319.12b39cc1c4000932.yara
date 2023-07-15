
rule m2319_12b39cc1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.12b39cc1c4000932"
     cluster="m2319.12b39cc1c4000932"
     cluster_size="642"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['91bcec122497f96ddb30ccddd93edc5973138de8','2175c309e289cdda60ed64592a6a0787625ef6af','fc7d284f6416b52359cb4c8db11e42ca2ae86c3b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.12b39cc1c4000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
