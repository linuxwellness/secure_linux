
rule j2321_32bb280600001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.32bb280600001912"
     cluster="j2321.32bb280600001912"
     cluster_size="41"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['09fd34218f2589bb2a81eeb10ad172d1','0d5389d6b04782176b6711b6422f3dcc','3fc9835d0165d2e79166354e924f0492']"

   strings:
      $hex_string = { b4658715d9a1333b14b3c363d9616c6a329bea86caeb31d067ab2f1f9d6d4e979c6a9ada98b79fdab87443e5fd897796a4d7555fee3871f4c78d69cbe4b5531b }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
