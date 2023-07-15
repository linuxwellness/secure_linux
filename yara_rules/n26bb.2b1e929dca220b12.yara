
rule n26bb_2b1e929dca220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2b1e929dca220b12"
     cluster="n26bb.2b1e929dca220b12"
     cluster_size="57"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="incredimail perion engine"
     md5_hashes="['9945fc74ee9afcea53ee352cb9a34e8e735c9d0b','74c04e41dea0985da275b9ccfa92fde9eb5f1140','395f1a9a22b3eabc8776484b993fe1fa13e5b8a9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2b1e929dca220b12"

   strings:
      $hex_string = { 6d1d3ded41650a53dd160fa1cd8e2a015282fdd260f63ed7e6a7fb9058f5aa4a42514e30271839bb34741bf98b724498471992052be8753815b368995ec797ea }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
