
rule i3f7_230d2b55ea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3f7.230d2b55ea210912"
     cluster="i3f7.230d2b55ea210912"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd script html"
     md5_hashes="['050f8dd2be6e7f15002672c9bd8abecc','069d57ea5bc931b8b23b5c12da17b207','edf5deb2884f786fa2479afa0f8313c8']"

   strings:
      $hex_string = { 636861727365743d77696e646f77732d31323532223e0d0a3c7469746c653e457863656c204f6e6c696e65202d2030394b534a444a52343834333938344e4639 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
