
rule o26bb_5986b4c3de630b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.5986b4c3de630b32"
     cluster="o26bb.5986b4c3de630b32"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious rootkit"
     md5_hashes="['7b87d8cc9c2e280eef4b379212d568968258880f','8acefdfdb5484fc21bb95e8fc4beabb091c755ed','9b2b15219a1d21773ce5fea5bf9bc3b162915452']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.5986b4c3de630b32"

   strings:
      $hex_string = { 8b08420254119b08451140043904ab065f11730f130e980fd108d808c20cdd09ff0322064d05df10b204ff0fc409970a740b740be808f808380949094b094409 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
