
rule n2319_69945ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.69945ec1c4000b12"
     cluster="n2319.69945ec1c4000b12"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['f58be8b7ba9ae9626ec144e47e86b83bea6ce9a3','ada0b71a52703163757262451603e22f94b34ee0','fda30b7c45014b4ced989351272edffa5732e379']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.69945ec1c4000b12"

   strings:
      $hex_string = { 3b66756e6374696f6e20676574546f74616c4d656d6f727928297b72657475726e20544f54414c5f4d454d4f52597d4845415033325b305d3d31363638353039 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
