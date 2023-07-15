
rule m2318_29394008d7a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.29394008d7a30912"
     cluster="m2318.29394008d7a30912"
     cluster_size="11"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['06cc5766de55f94374595b549122395f','174fc953c62353f3f170e2e0a6cd98ae','ff8e5f0116285952027bbdb38a03f3bc']"

   strings:
      $hex_string = { 2043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e6420 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
