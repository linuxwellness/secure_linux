
rule i2321_04b48b2cc36b0b31
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.04b48b2cc36b0b31"
     cluster="i2321.04b48b2cc36b0b31"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['24037e9d410c38d1e539bffd2845dd3f','50528a0b0aaf3f1a2a72478ed1e448c9','bb8fbf547817b6616856b64c0ad5dffb']"

   strings:
      $hex_string = { af3f4ab29a2ca22ddfb97afcaeb9397efde68bf7e49fe2de75c6ff088f5c5276ddadf3ff33fd723c5b1f36f7f60da65da3e5eec1913dc3a5071e1f2af5a7c9b1 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
