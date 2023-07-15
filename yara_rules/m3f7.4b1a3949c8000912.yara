
rule m3f7_4b1a3949c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.4b1a3949c8000912"
     cluster="m3f7.4b1a3949c8000912"
     cluster_size="16"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker likejack clicker"
     md5_hashes="['0919f2a8e77302e0ad422062a7b4642a','0954616dcdb3b42f472975c23418be15','f8dbeffbbd0b69920ce0db48c8ef8fc6']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
