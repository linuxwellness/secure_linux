
rule m2319_158db1e9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.158db1e9ca000b32"
     cluster="m2319.158db1e9ca000b32"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['c715c033e709a2ad1ad5020d118fe72bf1d5da72','81f9610145084e0d9f3fe1893128867d23f2f700','6fcc45ff62aa5f578ad5c97307460a0bf75e4913']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.158db1e9ca000b32"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
