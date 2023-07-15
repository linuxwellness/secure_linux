
rule k2318_52945adbc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.52945adbc6220b12"
     cluster="k2318.52945adbc6220b12"
     cluster_size="939"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['ce038330e104127f91257c55ad93d2ee273cf4e7','70c2d5123d99ed78161ee73de4a8dc4cbbcd21fb','0f43ade227b710e1df6aa243ddd3224718bc0f45']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.52945adbc6220b12"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
