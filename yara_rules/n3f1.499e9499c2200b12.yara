
rule n3f1_499e9499c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.499e9499c2200b12"
     cluster="n3f1.499e9499c2200b12"
     cluster_size="217"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="obfus androidos abea"
     md5_hashes="['01e2cd3b225a9fb46f644948f578f5d1','02cc916479cf6f5666041ca3780adb59','152a4d079bf199e4ce0f288fd655c6a5']"

   strings:
      $hex_string = { 07803b0db5c6d0986d168a29f57d9a05096e5aadaa6a9b82340c657d7fbfd96c589c99558b59d72ef6e63fdaf81637cdbb8dce17e8fa568e1ec06f4c25f2141b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
