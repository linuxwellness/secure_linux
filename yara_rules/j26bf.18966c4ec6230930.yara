
rule j26bf_18966c4ec6230930
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.18966c4ec6230930"
     cluster="j26bf.18966c4ec6230930"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo genx malicious"
     md5_hashes="['72b9ea2a9103069446f1e8b62f286f0b27fbbb67','ba6f7328d7b0410c10120b1ac2e0c8b39adc5911','480c81951a16b3059077d33338e39e95913a1664']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.18966c4ec6230930"

   strings:
      $hex_string = { 756c740044656661756c740073656e646572006500646973706f73696e670076616c75650053797374656d2e5265666c656374696f6e00417373656d626c7954 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
