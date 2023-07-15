
rule k3e9_0b9adcc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b9adcc9cc000b12"
     cluster="k3e9.0b9adcc9cc000b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['364585844d9ce0f6af8397222c547d47','9089ae5c59f70692f2d29c11d7a699f3','f46b593e2b05141f945c58453465a9c9']"

   strings:
      $hex_string = { 34b014d971cf839e178db5621e74be6d4b432f38a5c5737e69f19c0d36c046eec4e37b88b8c2dc41c7e2c6c97ca710df6ee7bff176bbdd40aa22e04c60f4efae }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
