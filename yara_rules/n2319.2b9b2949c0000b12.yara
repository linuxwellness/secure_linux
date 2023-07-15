
rule n2319_2b9b2949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.2b9b2949c0000b12"
     cluster="n2319.2b9b2949c0000b12"
     cluster_size="185"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack script clicker"
     md5_hashes="['5f4d02c2081d33b4f60446ff1c3170177abe32a7','8124b879b1d772256b9c1c0fe06c56c56412b6a1','50cc4a23dc7fd66ad6b58801785cf1af7e5713fe']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.2b9b2949c0000b12"

   strings:
      $hex_string = { 5d2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e7465 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
